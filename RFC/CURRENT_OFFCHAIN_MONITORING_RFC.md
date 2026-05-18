RFC — Offchain Attack Surface Monitoring
=========================================

**Status**: Approved
**Author**: Carlos Polop
**Date**: 2026-04-13

--

## Table of Contents

1. [Overview](#1-overview)
2. [Goals & Non-Goals](#2-goals--non-goals)
3. [Required Input from Organisations](#3-required-input-from-organisations)
4. [Entity Model — Sentry Integration](#4-entity-model--sentry-integration)
5. [Relationship Model](#5-relationship-model)
6. [Monitoring Frequencies](#6-monitoring-frequencies)
7. [Weekly Full Scan — bbot Pipeline](#7-weekly-full-scan--bbot-pipeline)
8. [Deferred Scope](#8-deferred-scope)
9. [Architecture Overview](#9-architecture-overview)
10. [Database Schema Changes](#10-database-schema-changes)
11. [Module System Integration](#11-module-system-integration)
12. [API Surface](#12-api-surface)
13. [Alerting & Diffing](#13-alerting--diffing)
14. [Migration from Current NetworkNode](#14-migration-from-current-networknode)
15. [Open Questions](#15-open-questions)

--

## 1. Overview

GuardianSentry currently performs **onchain** analysis (smart contract graph construction, fuzzing, mutation testing). This RFC defines the **offchain attack surface monitoring** data model and weekly discovery integration: domains, IPs, URLs, network services, emails, cloud resources, repositories, mobile apps, social profiles, and offchain findings.

The proposal was created based on the combination of two reconnaissance engines:

 **bbot** — modular attack surface scanner with 145+ modules covering DNS, HTTP, OSINT, cloud, code, and vulnerability discovery.
 **hackermate** — graph-based enrichment engine with Neo4j-backed node/relationship model, worker queues, and reputational scoring.

The offchain monitoring maps all discovered assets into GuardianSentry's existing `WorldGraph`, extending the graph with **new node types** and **typed relationships**, while keeping dependent objects as model tables and security findings in `TrackedFinding`. The goal is a unified onchain + offchain view of an organisation's attack surface without duplicate representations.

--

## 2. Goals & Non-Goals

### Goals

 Discover and monitor an organisation's external attack surface via recurring full scans.
 Map all offchain entities into Sentry's `WorldGraph` as first-class nodes with rich attributes.
 Provide a **weekly full scan** cadence for broad attack-surface discovery.
 Detect changes (new subdomains, expired certificates, DNS record changes, new vulnerabilities, leaked credentials) and surface alerts.
 Integrate with the existing Sentry build/work pipeline and UI.
 Keep it as cheap as possible

### Current Non-Goals

 Real-time continuous monitoring. This is explicitly deferred until the weekly scan path and typed persistence are complete.
 Active exploitation or penetration testing.
 Building a full SIEM or log aggregation system -- These is pure external monitorization.

--

## 3. Required Input from Organisations

When onboarding a new World for offchain monitoring, the organisation must provide:

### 3.1 Required Fields

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `domains` | `string[]` | Root domains to monitor (wildcard scope: `*.domain.com`) | `["guardianaudits.com", "guardian.xyz"]` |

### 3.2 Optional Fields (Enhance Coverage)

| Field | Type | Description | Example |
|-------|------|-------------|---------|
| `excluded_domains` | `string[]` | Domains to explicitly exclude from scope | `["cdn.cloudflare.com"]` |
| `excluded_ips` | `string[]` | IPs to exclude | `["127.0.0.1"]` |

### 3.3 World Model Extension

Instead of grouping all offchain configuration into a single JSON field, the currently implemented offchain settings live as **top-level columns** on the `World` model. Root domains continue to use the existing `World.domains` field.

```typescript
// New top-level fields on World entity (src/db/models/World.ts)
offchainStatus: p.string().length(20).default('disabled'),   // 'disabled' | 'active' | 'paused'
offchainExcludedDomains: p.json<string[]>().nullable(),
offchainExcludedIps: p.json<string[]>().nullable(),
offchainEnableRealTimeMonitoring: p.boolean().default(false),
offchainWeeklyScanDay: p.string().length(10).default('sunday'),
offchainWeeklyScanTime: p.string().length(5).default('00:00'),
lastWeeklyScanAt: p.datetime().nullable(),
nextWeeklyScanAt: p.datetime().nullable(),
```

### 3.4 Effective Scope Enforcement

The implemented weekly scan treats the World's initial inputs as the only authority for scope expansion:

1. **Domains / subdomains**: only FQDNs that are equal to, or are subdomains of, the seeded domain roots are allowed to become `DNS_NAME`/`DNS_NAME_UNRESOLVED` entities and downstream scan subjects. Domain-like strings found in attributes such as phishing history, WHOIS payloads, MX answers, TXT content, or external CNAME targets may still be stored as attributes on an in-scope node, but they do **not** widen scan scope and must not trigger downstream analysis or notifications as standalone domain assets.
2. **Code repositories**: only repositories that exactly match a seeded `code_repository` URL, or that belong to a seeded `code_repository_owner` / `org_stub`, are allowed to remain in the BBOT event stream and become `CodeRepositoryNode`s. Repositories discovered outside that allowlist are dropped before downstream repo-analysis modules fan out on them.
3. **IP addresses**: absent an explicit IP seed, only IPs learned from `A` / `AAAA` resolution of an in-scope domain are allowed to become `IPAddressNode`s or to drive downstream IP-based analysis (`OPEN_*_PORT`, `PROTOCOL`, `TLS_CERTIFICATE`, geolocation, reputation, etc.). IPs found in other DNS record types such as `MX`, `SOA`, or unrelated payload attributes may still be stored inside the parent domain's raw attributes/history, but they do **not** become standalone IP assets.
4. **URLs**: URLs are only allowed when their host is already allowed by the effective world scope. That means GuardianSentry accepts URLs that were explicitly configured as scan seeds, plus any URLs whose host is an allowed domain/subdomain or an allowed IP/IP-range target. URLs whose hosts fall outside that scope are dropped and must not create standalone `URLObject`s or downstream web-analysis events.

This enforcement is implemented in two layers:

1. **BBOT intercept filtering** drops out-of-scope `DNS_NAME`, `CODE_REPOSITORY`, and IP-driven follow-on events before scan modules can continue expanding on them.
2. **GuardianSentry ingestion** re-checks scope before persisting nodes, edges, alerts, or tracked findings.

When an operator launches an ad hoc scan with explicit `scanTargets`, those targets are treated only as the **starting subset** for the run. The system still loads the World's original configured scope and applies the same allowlist rules to:

1. the requested ad hoc targets themselves, and
2. every new domain, repository, IP, and URL discovered while scanning from those targets.

In other words, requested scan targets can narrow the scan, but they cannot widen the World's authority boundary.

--

## 4. Entity Model — Sentry Integration

### 4.1 Design Decision: Nodes, Model Tables, and Findings

The offchain model uses three categories of entities, with exactly one canonical representation for each concept:

1. **WorldGraph Nodes** — infrastructure and identity entities that participate in the graph as first-class `WorldNode` subtypes (DomainNode, IPAddressNode, etc.). These have typed edges connecting them.
2. **Model Tables** — entities that are closely related to a single parent node and are better modeled as regular ORM tables with a foreign key rather than graph nodes. `URLObject` belongs to a Domain or IP, and `EmailAddress` belongs to a Domain.
3. **TrackedFindings** — vulnerability and secret/credential discoveries are tracked via Sentry's existing `TrackedFinding` system rather than as separate graph nodes, keeping security findings in one unified place.

**Rationale**: `URLObject` and `EmailAddress` are dependent objects that always belong to a parent. Promoting them to graph nodes creates duplicate representations and unnecessary edge complexity. Security findings already have a well-established home in `TrackedFinding`, with severity, validation, and recommendation fields.

### 4.2 Deduplication Strategy

Every offchain entity (nodes, model tables, and findings) uses a **UUID v7** as its primary key. UUID v7 is time-sortable and globally unique.

**Current deduplication strategy**:

1. Each entity type has a natural identity scoped by `worldGraphId` or `worldId`.
2. The database enforces uniqueness through composite unique indexes such as `(worldGraphId, name)` for `DomainNode` and `(worldId, url)` for `URLObject`.
3. Service-layer upsert logic preserves that single-representation model by merging BBOT enrichments into the existing row.
4. Every canonical offchain object table (`DomainNode`, `IPAddressNode`, `IPRangeNode`, `NetworkServiceNode`, `CloudResourceNode`, `CodeRepositoryNode`, `SocialProfileNode`, `MobileAppNode`, `URLObject`, and `EmailAddress`) includes `discoveredByModules text[]`.

`discoveredByModules` stores the deduplicated BBOT module names that emitted events for that object identity. For example, if `crt`, `subfinder`, and `dnsdumpster` all discover the same `DNS_NAME`, the single stored `DomainNode` row is updated to include all three module names. The same rule applies to IPs, IP ranges, network services/open ports, URLs, emails, cloud resources, code repositories, social profiles, and mobile apps.

The ingester reads BBOT `event.module` as the source module. When a later event from a different module maps to an already-existing object, GuardianSentry updates `discoveredByModules` on that row instead of creating a duplicate object. BBOT may still suppress exact duplicate events from the same emitting module, but discoveries from different modules must reach GuardianSentry as separate emitted events, or BBOT must otherwise expose their module attribution, so this provenance field can be updated. GuardianSentry offchain scans force `modules.stdout.accept_dupes=true` for JSON output to preserve those cross-module duplicate events.

### 4.3 Extended WorldNodeType Enum

```typescript
export enum WorldNodeType {
  // Existing onchain
  Contract = 'contract',

  // Offchain — Core Assets
  OffchainDomain = 'offchain_domain',
  IPAddress = 'ip_address',
  IPRange = 'ip_range',

  // Offchain — Infrastructure
  NetworkService = 'network_service',
  CloudResource = 'cloud_resource',

  // Offchain — Assets
  CodeRepository = 'code_repository',
  MobileApp = 'mobile_app',

  // Offchain — Identity
  SocialProfile = 'social_profile',
}
```

> **Removed from graph nodes**: `URLObject` and `EmailAddress` are model tables (Section 4.5). Vulnerability and secret discoveries are tracked as `TrackedFinding` records (Section 4.6). There is no duplicate node form for those concepts.

### 4.4 Node Definitions

Each entity type becomes a MikroORM entity extending `WorldNode` via TPT inheritance.

Below is the current implemented attribute specification per node type. Common fields are inherited from `WorldNode`, and subtype tables include `createdAt` / `updatedAt` where implemented. All offchain node and model tables also include `discoveredByModules text[]`, which records the BBOT modules that discovered the canonical object.

--

#### 4.4.1 DomainNode

> A DNS domain or subdomain. Central object for attack surface mapping.

**Identity**: `name` (FQDN)

| Column | DB Type | Description |
|--------|---------|-------------|
| `name` | `varchar(253)` | FQDN |
| `is_subdomain` | `boolean` | Whether this is a subdomain |
| `parent_domain_id` | `uuid` | FK → DomainNode (nullable) |
| `is_resolved` | `boolean` | Whether resolution succeeded |
| `is_wildcard` | `boolean` | Wildcard DNS detected |
| `wildcard_ips` | `text[]` | Wildcard IPs |
| `dns_a` | `text[]` | A records |
| `dns_aaaa` | `text[]` | AAAA records |
| `dns_cname` | `text[]` | CNAME records |
| `dns_mx` | `jsonb` | MX records |
| `dns_ns` | `text[]` | NS records |
| `dns_txt` | `text[]` | TXT records |
| `dns_soa` | `jsonb` | SOA record |
| `dns_srv` | `jsonb` | SRV records |
| `dns_caa` | `jsonb` | CAA records |
| `dns_ptr` | `text[]` | PTR records |
| `spf` | `text` | SPF record |
| `dmarc` | `text` | DMARC record |
| `dkim_selectors` | `jsonb` | DKIM selectors |
| `bimi` | `text` | BIMI record |
| `tls_rpt` | `text` | TLS-RPT record |
| `certificate` | `jsonb` | TLS certificate metadata |
| `cert_subject_cn` | `varchar(255)` | Subject CN |
| `cert_issuer_cn` | `varchar(255)` | Issuer CN |
| `cert_fingerprint_sha256` | `varchar(64)` | Fingerprint |
| `cert_san_domains` | `text[]` | SAN domains |
| `cert_not_after` | `timestamptz` | Validity end |
| `cert_is_expired` | `boolean` | Expired flag |
| `registrar` | `varchar(255)` | Registrar |
| `registration_date` | `timestamptz` | Registration date |
| `expiration_date` | `timestamptz` | Expiration date |
| `updated_date` | `timestamptz` | WHOIS update date |
| `registrant_name` | `varchar(255)` | Registrant name |
| `registrant_email` | `varchar(255)` | Registrant email |
| `registrant_org` | `varchar(255)` | Registrant org |
| `registrant_country` | `varchar(10)` | Registrant country |
| `dnssec` | `boolean` | DNSSEC enabled |
| `whois_status` | `text[]` | WHOIS statuses |
| `zone_transfer_possible` | `boolean` | AXFR allowed |
| `phishing_like_domains_history` | `jsonb` | Similar-domain history |
| `ip_history` | `jsonb` | IP history |
| `is_google_workspace` | `boolean` | Google Workspace domain |
| `is_entraid_workspace` | `boolean` | Entra ID domain |

--

#### 4.4.2 IPAddressNode

> An IPv4 or IPv6 address that is explicitly seeded or derived from `A` / `AAAA` resolution of an in-scope domain.

**Identity**: `address` (IP string)

| Column | DB Type | Description |
|--------|---------|-------------|
| `address` | `varchar(45)` | IP address |
| `version` | `varchar(2)` | `v4` or `v6` |
| `is_private` | `boolean` | RFC1918 private |
| `reverse_dns` | `text[]` | PTR records |
| `country` | `varchar(10)` | Country code |
| `region` | `varchar(100)` | State/region |
| `city` | `varchar(100)` | City |
| `latitude` | `float` | Latitude |
| `longitude` | `float` | Longitude |
| `asn` | `integer` | AS number |
| `isp` | `varchar(255)` | ISP |
| `is_cdn` | `boolean` | CDN address |
| `cdn_name` | `varchar(100)` | CDN provider |
| `cloud_provider` | `varchar(50)` | Cloud provider |
| `provider_type` | `varchar(20)` | hosting/residential/business/education/government |
| `is_vpn` | `boolean` | Known VPN |
| `is_proxy` | `boolean` | Known proxy |
| `is_tor` | `boolean` | Tor exit node |
| `risk_score` | `integer` | 0-100 |
| `os` | `varchar(100)` | Detected OS |
| `blacklisted` | `boolean` | On any blacklist |
| `blacklist_sources` | `jsonb` | `{source, type, listed_date}[]` |

--

#### 4.4.3 IPRangeNode

> A CIDR block / network range.

**Identity**: `cidr` (CIDR notation)

| Column | DB Type | Description |
|--------|---------|-------------|
| `cidr` | `varchar(50)` | CIDR notation |
| `version` | `varchar(2)` | `v4` or `v6` |
| `size` | `integer` | Number of addresses |
| `range_name` | `varchar(255)` | Range name from RIR |
| `country` | `varchar(10)` | Country code |
| `asn` | `integer` | AS number |

--

#### 4.4.4 NetworkServiceNode

> Network service running on IP:port. Combines OPEN_TCP_PORT, OPEN_UDP_PORT, PROTOCOL.

**Identity**: `endpoint` (`ip:port/transport`)

| Column | DB Type | Description |
|--------|---------|-------------|
| `endpoint` | `varchar(100)` | `ip:port/transport` |
| `ip` | `varchar(45)` | IP address |
| `port` | `integer` | Port number |
| `transport` | `varchar(3)` | `tcp` or `udp` |
| `protocol` | `varchar(50)` | Application protocol |
| `product` | `varchar(200)` | Software product |
| `version` | `varchar(100)` | Product version |
| `banner` | `text` | Service banner |
| `cpes` | `text[]` | CPE identifiers |
| `os` | `varchar(100)` | Detected OS |
| `tls_version` | `varchar(20)` | TLS version |
| `cipher_suite` | `varchar(100)` | Cipher |
| `certificate` | `jsonb` | Same TLS cert structure |
| `cert_subject_cn` | `varchar(255)` | Derived cert subject CN |
| `cert_issuer_cn` | `varchar(255)` | Derived cert issuer CN |
| `cert_not_after` | `timestamptz` | Derived cert validity end |
| `cert_fingerprint_sha256` | `varchar(64)` | Derived cert fingerprint |
| `cert_is_expired` | `boolean` | Derived expired flag |
| `cert_san_domains` | `text[]` | Derived SAN domains for coverage queries |
| `extra_info` | `text` | Additional info |

--

#### 4.4.5 CloudResourceNode

> Cloud resource — S3, GCS, Azure Blob, tenants, etc.

**Identity**: `resource_id` (`provider:type:identifier`)

| Column | DB Type | Description |
|--------|---------|-------------|
| `resource_id` | `varchar(500)` | `provider:type:id` |
| `provider` | `varchar(20)` | aws/gcp/azure/digitalocean/other |
| `resource_type` | `varchar(30)` | storage_bucket/tenant/account/function/database/vm/container_registry |
| `name` | `varchar(255)` | Resource name |
| `resource_url` | `text` | Access URL |
| `region` | `varchar(50)` | Cloud region |
| `is_public` | `boolean` | Publicly accessible |
| `permissions` | `text[]` | Discovered permissions |

--

#### 4.4.6 CodeRepositoryNode

> Source code repository that is explicitly seeded or belongs to an allowed seeded owner/org.

**Identity**: `repo_url` (URL)

| Column | DB Type | Description |
|--------|---------|-------------|
| `repo_url` | `text` | Repository URL |
| `platform` | `varchar(20)` | github/bitbucket/azure_devops/self_hosted |
| `owner` | `varchar(200)` | Repo owner/org |
| `repo_name` | `varchar(200)` | Repository name |
| `is_public` | `boolean` | Publicly accessible |
| `description` | `text` | Repo description |
| `default_branch` | `varchar(100)` | Default branch |
| `stars` | `integer` | Star count |
| `forks` | `integer` | Fork count |
| `repo_created_date` | `timestamptz` | Creation date |

--

#### 4.4.7 SocialProfileNode

> Social media profile. Links to an EmailAddress via FK.

**Identity**: `platform_handle` (`platform:username`)

| Column | DB Type | Description |
|--------|---------|-------------|
| `platform_handle` | `varchar(300)` | `platform:username` |
| `platform` | `varchar(20)` | twitter/linkedin/facebook/github/etc. |
| `profile_url` | `text` | Full profile URL |
| `display_name` | `varchar(200)` | Display name |
| `avatar_url` | `text` | Profile picture |
| `bio` | `text` | Bio |
| `location` | `varchar(200)` | Location |
| `website` | `text` | Linked website |
| `verified` | `boolean` | Verified account |
| `is_private` | `boolean` | Private account |
| `created_at_platform` | `timestamptz` | Account creation |
| `followers` | `integer` | Follower count |
| `following` | `integer` | Following count |
| `posts_count` | `integer` | Post count |
| `company` | `varchar(200)` | Company |
| `email_id` | `uuid` | FK → EmailAddress (nullable) |

--

#### 4.4.8 MobileAppNode

> Mobile application (iOS/Android).

**Identity**: `store_id` (`platform:bundle_id`)

| Column | DB Type | Description |
|--------|---------|-------------|
| `store_id` | `varchar(300)` | `platform:bundle_id` |
| `platform` | `varchar(10)` | ios/android |
| `bundle_id` | `varchar(255)` | Bundle ID |
| `app_name` | `varchar(255)` | App name |
| `store_url` | `text` | Store URL |
| `developer` | `varchar(255)` | Developer name |
| `app_version` | `varchar(50)` | Latest version |
| `description` | `text` | App description |
| `app_permissions` | `text[]` | Requested permissions |

--

### 4.5 Model Tables (Non-Node Entities)

These entities are modeled as regular ORM tables with foreign keys to their parent nodes rather than as `WorldNode` subtypes. They do **not** participate in the edge graph.

--

#### 4.5.1 URLObject

> An HTTP(S) endpoint. Related to the DomainNode or IPAddressNode it belongs to. Not a graph node.

**Identity**: `url` (full URL)

| Column | DB Type | Description |
|--------|---------|-------------|
| `id` | `uuid` | UUID v7 primary key |
| `world_id` | `uuid` | FK → World |
| `domain_id` | `uuid` | FK → DomainNode (nullable) |
| `ip_address_id` | `uuid` | FK → IPAddressNode (nullable — for IP-based URLs) |
| `url` | `text` | Full URL (unique per World) |
| `scheme` | `varchar(10)` | http/https |
| `host` | `varchar(253)` | Hostname or IP |
| `port` | `integer` | Port number |
| `is_verified` | `boolean` | Whether URL was actually visited |
| `status_code` | `integer` | HTTP status code |
| `title` | `text` | Page title |
| `content_type` | `varchar(100)` | Content-Type |
| `content_length` | `integer` | Body size |
| `response_headers` | `jsonb` | `{name, value}[]` |
| `response_body_hash` | `varchar(64)` | SHA-256 of body |
| `technologies` | `jsonb` | `{name, version?, category?, confidence?}[]` |
| `server` | `varchar(255)` | Server header |
| `waf` | `jsonb` | `{name, info?}` |
| `csp` | `text` | Content-Security-Policy |
| `cors_origin` | `varchar(500)` | Access-Control-Allow-Origin |
| `hsts` | `boolean` | HSTS present |
| `x_frame_options` | `varchar(100)` | X-Frame-Options |
| `cookies` | `jsonb` | `{name, value, domain, secure, httponly, samesite}[]` |
| `certificate` | `jsonb` | Same structure as DomainNode certificate |
| `cert_subject_cn` | `varchar(255)` | Derived cert subject CN |
| `cert_issuer_cn` | `varchar(255)` | Derived cert issuer CN |
| `cert_not_after` | `timestamptz` | Derived cert validity end |
| `cert_fingerprint_sha256` | `varchar(64)` | Derived cert fingerprint |
| `cert_is_expired` | `boolean` | Derived expired flag |
| `cert_san_domains` | `text[]` | Derived SAN domains for coverage queries |
| `created_at` | `timestamptz` | Discovery time |
| `updated_at` | `timestamptz` | Last update |

--

#### 4.5.2 EmailAddress

> An email address found during recon. Related to the DomainNode of its email domain. Not a graph node.

**Identity**: `address` (full email)

| Column | DB Type | Description |
|--------|---------|-------------|
| `id` | `uuid` | UUID v7 primary key |
| `world_id` | `uuid` | FK → World |
| `domain_id` | `uuid` | FK → DomainNode (the domain part of the email) |
| `address` | `varchar(320)` | Full email (unique per World) |
| `is_valid` | `boolean` | Deliverable |
| `is_freemail` | `boolean` | Gmail, Yahoo, etc. |
| `is_disposable` | `boolean` | Temporary service |
| `is_role` | `boolean` | Role account |
| `is_catchall` | `boolean` | Domain accepts all |
| `first_name` | `varchar(100)` | First name |
| `last_name` | `varchar(100)` | Last name |
| `full_name` | `varchar(200)` | Full name |
| `phone` | `varchar(30)` | Phone |
| `job_title` | `varchar(200)` | Job title |
| `created_at` | `timestamptz` | Discovery time |
| `updated_at` | `timestamptz` | Last update |

--

### 4.6 Findings Integration (Vulnerability & Secret → TrackedFinding)

Vulnerabilities and exposed secrets discovered by bbot are **not** modeled as graph nodes. Instead, they are persisted as `TrackedFinding` records using Sentry's existing findings system.

`TrackedFinding` already provides: `severity`, `title`, `description`, `recommendation`, `poc`, `valid`, `invalidReason`, and `worldId` FK.

#### Mapping bbot Vulnerabilities → TrackedFinding

| bbot Field | TrackedFinding Field |
|-----------|---------------------|
| CVE ID + vuln name | `title` |
| CVSS severity mapping | `severity` (`critical`, `high`, `medium`, `low`) |
| Vulnerability description | `description` |
| Remediation/solution | `recommendation` |
| Proof/evidence | `poc` |
| Affected host + URL + port | `location` |

#### Mapping Exposed Secrets → TrackedFinding

| Secret Field | TrackedFinding Field |
|-------------|---------------------|
| Secret type + context | `title` (e.g. "Exposed API key found on pastebin.com") |
| Severity by type (private_key → critical, api_key → high) | `severity` |
| Context snippet + source URL | `description` |
| "Rotate immediately / revoke token" | `recommendation` |
| Source URL + file path + line | `location` |
| Matching content excerpt | `poc` |

--

## 5. Relationship Model

### 5.1 Design Decision: Typed Relationships via `OffchainEdge`

We introduce a new edge subtype `OffchainEdge` extending `WorldEdge` via STI (alongside existing `ContractEdge`). All offchain relationships use a **typed `relationship` string** from a fixed enum.

**Why typed over generic?** Typed relationships enable:

 Querying specific relationship paths (e.g. "which domains resolve to this IP?")
 Rendering meaningful graph visualisations
 Enforcing valid source→target type constraints
 Diffing relationships between scans

> **Note on parent relationships**: `URLObject` and `EmailAddress` are non-node entities and use foreign keys for their parent relationships instead of graph edges (see Section 4.5). `SocialProfileNode` remains a graph node and additionally has an optional FK to `EmailAddress`. Vulnerability and Secret findings are TrackedFinding records and do not participate in the graph.

### 5.2 OffchainEdge Schema

```typescript
export enum OffchainRelationship {
  // Domain relationships
  ResolvesTo = 'resolves_to',           // Domain → IPAddress
  IsSubdomainOf = 'is_subdomain_of',    // Domain (sub) → Domain (parent)
  CnameTo = 'cname_to',                 // Domain → Domain

  // IP relationships
  InRange = 'in_range',                  // IPAddress → IPRange
  RunsService = 'runs_service',          // IPAddress → NetworkService

  // IP Range relationships
  SubnetOf = 'subnet_of',               // IPRange (child) → IPRange (parent)

  // NetworkService relationships
  RunsOn = 'runs_on',                   // NetworkService → IPAddress

  // Cloud relationships
  AssociatedDomain = 'associated_domain', // CloudResource → Domain
}
```

> **Removed relationships vs previous RFC**:
> - `Contains` (IPRange → IPAddress) — navigable via `InRange` edges in reverse.
> - `HasSubnet` (IPRange → IPRange) — navigable via `SubnetOf` edges in reverse.
> - `HasSubdomain` — replaced by `IsSubdomainOf` (subdomain points to parent, matching FK direction).
> - `HasEmail`, `BelongsToDomain` — EmailAddress has FK to DomainNode.
> - `HasSocial`, `BelongsTo`, `HasUsername` — SocialProfileNode has FK to EmailAddress.
> - `Hosts`, `HostedOn` — URLObject has FK to DomainNode / IPAddressNode.
> - `Serves` — URLObject relates to NetworkService through its Domain/IP parent.
> - `Affects`, `FoundIn`, `ContainsSecret` — Findings use TrackedFinding with `location`.
> - `OwnedBy`, `OwnsRepo` — CodeRepositoryNode.`owner` is a string field.

### 5.3 OffchainEdge Entity

```typescript
// New STI subtype of WorldEdge
export class OffchainEdge extends WorldEdge {
  // relationship field (inherited) contains the OffchainRelationship value
  // No additional columns needed — the typed relationship string is sufficient
}
```

The `discriminatorMap` in `WorldEdge` is updated:

```typescript
discriminatorMap: {
  base: 'WorldEdge',
  contract: 'ContractEdge',
  offchain: 'OffchainEdge',
}
```

### 5.4 Relationship Validity Matrix

| Source Node | Relationship | Target Node |
|-------------|-------------|-------------|
| Domain | `resolves_to` | IPAddress |
| Domain (subdomain) | `is_subdomain_of` | Domain (parent) |
| Domain | `cname_to` | Domain |
| IPAddress | `in_range` | IPRange |
| IPAddress | `runs_service` | NetworkService |
| IPRange | `subnet_of` | IPRange (parent) |
| NetworkService | `runs_on` | IPAddress |
| CloudResource | `associated_domain` | Domain |

### 5.5 Non-Edge Relationships (Foreign Keys)

| Entity | FK Column | Target | Description |
|--------|-----------|--------|-------------|
| DomainNode | `parent_domain_id` | DomainNode | Subdomain → parent domain |
| URLObject | `domain_id` | DomainNode | URL belongs to this domain |
| URLObject | `ip_address_id` | IPAddressNode | URL belongs to this IP (for IP-based URLs) |
| EmailAddress | `domain_id` | DomainNode | Email's domain part |
| SocialProfileNode | `email_id` | EmailAddress | Social profile's associated email |

--

## 6. Monitoring Frequencies

The system operates on two cadences:

| Cadence | Frequency | Purpose | Resource Profile |
|---------|-----------|---------|-----------------|
| **Weekly Full Scan** | Once per week (configurable day/time) | Broad attack surface discovery using bbot `all-but-intense-http` template | High — spawns bbot process, runs many modules, port scans, active HTTP requests |
| **Real-Time Continuous** | Every 30 seconds to 1 hour (configurable per monitor) | Track changes to critical signals in near real-time | Low — lightweight API calls, DNS lookups, CT log streams |

### 6.1 What Determines the Cadence?

| If the data source... | Then... |
|---|---|
| Requires active TCP connections (port scanning, HTTP crawling) | **Weekly** |
| Uses aggressive/deadly modules (nuclei, ffuf, brute-force) | **Weekly** |
| Can be queried via passive sources or free API in < 30s | **Real-Time candidate** |
| Could change frequently and has security impact (DNS, certs, subdomains) | **Real-Time** |
| Is slow, rate-limited, or has no change-detection benefit | **Weekly** |

--

## 7. Weekly Full Scan — bbot Pipeline

### 7.1 Overview

Weekly scans run with bbot's `all-but-intense-http.yaml` template to get broad coverage while avoiding the most expensive HTTP-intensive behavior.

The weekly scan is orchestrated using **Sentry's existing task queue infrastructure**: an EventBridge Scheduler triggers a seeder that populates the new `HeavyOffchain` SQS queue, and Sentry workers process those tasks using the standard `@asyncTask` pattern.

### 7.2 Infrastructure — Sentry Task Queue Integration

The weekly bbot pipeline reuses Sentry's existing infrastructure rather than introducing new AWS services:

 **EventBridge Scheduler**: triggers the weekly global kickoff at **Sunday 00:00 UTC** by writing an SQS message to `FAST_QUEUE` targeting `OffchainTasks.seedWeeklyScans`.
 **Seeder task** (`seedWeeklyScans`): an `@asyncTask(FAST_QUEUE)` method. Queries all active Worlds, creates a `ModuleRecord` per World (phase `build`, type `OffchainWeeklyScan`, status `queued`), and enqueues one `HEAVY_OFFCHAIN_QUEUE` message per World via `.applyAsync()`.
 **`HEAVY_OFFCHAIN_QUEUE`** (new SQS queue): a new `QueueDefinition` added to `src/task-queue/queue/queues.ts` alongside the existing `FAST_QUEUE`, `SLOW_QUEUE`, and `CONVERSATION_QUEUE`. Uses `ACK_IMMEDIATE` because bbot scans are long-running and exceed the SQS visibility timeout.
 **Worker task** (`executeWeeklyScan`): an `@asyncTask(HEAVY_OFFCHAIN_QUEUE)` method. Delegates to `OffchainWeeklyScanModule.run()` — a new `WorldBuildingModule<OffchainWeeklyScanRecordData>` following the exact same pattern as `ContractGraphModule` and `BbotDiscoveryModule`.
 **RDS PostgreSQL**: persists entities, relationships, snapshots, and findings.
 **S3**: stores raw bbot JSONL output and scan artifacts for 2 weeks.

#### 7.2.1 New Queue Definition

```typescript
// src/task-queue/queue/queues.ts — added alongside FAST_QUEUE, SLOW_QUEUE, CONVERSATION_QUEUE
import { ACK_IMMEDIATE, type QueueDefinition } from './types.js'

export const HEAVY_OFFCHAIN_QUEUE: QueueDefinition = {
  name: process.env.HEAVY_OFFCHAIN_QUEUE_NAME || 'heavy-offchain',
  concurrency: 5,       // max 5 concurrent bbot scans
  ackMode: ACK_IMMEDIATE, // bbot scans are long-running; worker owns recovery
};

// Update ALL_QUEUES to include the new queue
export const ALL_QUEUES: QueueDefinition[] = [
  FAST_QUEUE,
  SLOW_QUEUE,
  CONVERSATION_QUEUE,
  HEAVY_OFFCHAIN_QUEUE, // new
];
```

#### 7.2.2 Task Class (following `worldTasks.ts` pattern)

```typescript
// src/offchain/tasks/offchainTasks.ts
import {
  asyncTask, initializeTasks, emitProgress,
  type SQSJob, type WithApplyAsync,
} from '../../task-queue/queue/index.js'
import { FAST_QUEUE } from '../../task-queue/queue/queues.js'
import { HEAVY_OFFCHAIN_QUEUE } from '../../task-queue/queue/queues.js'
import { OffchainOrchestrationService } from '../OffchainOrchestrationService.js'
import type { BuildingModuleType } from '../../sentry-worlds/models/Module.js'

export interface SeedWeeklyScansData {
  /** Optional: scan only this World. Omit to scan all active Worlds. */
  worldId?: string;
}

export interface ExecuteWeeklyScanData {
  worldId: string;
  moduleId: string;
}

export interface ExecuteExpansionScanData {
  worldId: string;
  moduleId: string;
  entityType: string;
  identityKey: string;
}

class OffchainTasks {
  private orchestration = new OffchainOrchestrationService();

  /**
   * Seeder — runs on FAST_QUEUE.
   * EventBridge triggers this on a weekly cron.
   * Creates one ModuleRecord per World and enqueues HEAVY_OFFCHAIN_QUEUE messages.
   */
  @asyncTask(FAST_QUEUE)
  async seedWeeklyScans(data: SeedWeeklyScansData, _job: SQSJob): Promise<void> {
    await this.orchestration.seedWeeklyScans(data.worldId);
  }

  /**
   * Worker — runs on HEAVY_OFFCHAIN_QUEUE (ACK_IMMEDIATE).
   * Executes the full bbot scan for a single World.
   * Follows the same lifecycle as worldTasks.executeBuildModule:
   * 1. Load ModuleRecord, verify status is 'queued'
   * 2. Set status → 'running'
   * 3. Call OffchainWeeklyScanModule.run(worldId, moduleId, recordData, emitProgress)
   * 4. Set status → 'completed' or 'failed'
   */
  @asyncTask(HEAVY_OFFCHAIN_QUEUE)
  async executeWeeklyScan(data: ExecuteWeeklyScanData, _job: SQSJob): Promise<void> {
    await this.orchestration.executeWeeklyScan(
      data.worldId, data.moduleId, emitProgress,
    );
  }

  /**
   * Expansion scan for a newly-discovered entity (Section 8.7).
   * Same queue as weekly scans — shared concurrency cap.
   */
  @asyncTask(HEAVY_OFFCHAIN_QUEUE)
  async executeExpansionScan(data: ExecuteExpansionScanData, _job: SQSJob): Promise<void> {
    await this.orchestration.executeExpansionScan(
      data.worldId, data.moduleId, data.entityType, data.identityKey, emitProgress,
    );
  }
}

export const offchainTasks = initializeTasks(
  new OffchainTasks(),
) as WithApplyAsync<OffchainTasks>;
```

#### 7.2.3 Building Module (following `BbotDiscoveryModule` pattern)

```typescript
// src/offchain/modules/OffchainWeeklyScanModule.ts
import type {
  WorldBuildingModule, BuildingModuleResult, ModuleEmitFn,
} from '../../sentry-worlds/models/Module.js'
import { BuildingModuleType } from '../../sentry-worlds/models/Module.js'
import { spawn } from 'child_process'
import { readLines, exitCode } from '../../bbot/process.js'
import { BBOT_CONFIG } from '../../bbot/config.js'
import { TrackedFinding } from '../../db/models/TrackedFinding.js'

export interface OffchainWeeklyScanRecordData {
  domains: string[];
  orgName?: string;
  githubOrgs?: string[];
  snapshotId?: string;
}

export class OffchainWeeklyScanModule
  implements WorldBuildingModule<OffchainWeeklyScanRecordData>
{
  readonly type = BuildingModuleType.OffchainWeeklyScan;

  async run(
    worldId: string,
    moduleId: string,
    data: OffchainWeeklyScanRecordData,
    emit: ModuleEmitFn,
  ): Promise<BuildingModuleResult> {
    const target = data.domains.join(',');

    try {
      // 1. Spawn bbot with all-but-intense-http preset
      const args = [
        '-t', target,
        '-n', `offchain-weekly-${worldId}`,
        '-p', 'all-but-intense-http',
        '--json', '-y',
      ];
      // Inject API keys from env vars via -c flags
      for (const [envVar, bbotKey] of Object.entries(BBOT_API_KEY_MAP)) {
        if (process.env[envVar]) args.push('-c', `${bbotKey}=${process.env[envVar]}`);
      }

      const proc = spawn('bbot', args, {
        env: { ...process.env, PIP_BREAK_SYSTEM_PACKAGES: '1' },
      });

      let nodesAdded = 0;

      // 2. Stream JSONL output — map events to typed entities
      for await (const line of readLines(proc)) {
        if (!line.trim()) continue;
        let event: any;
        try { event = JSON.parse(line); } catch { continue; }

        // Map bbot event → typed node/model table/TrackedFinding
        const result = await mapBbotEventToEntity(worldId, event);
        if (result) {
          nodesAdded++;
          // Emit real-time progress (same pattern as BbotDiscoveryModule)
          await emit(`world:${worldId}`, 'offchain:entityDiscovered', {
            worldId,
            entityType: result.entityType,
            entity: result.entity,
          });
        }
      }

      const code = await exitCode(proc);
      if (code !== 0) throw new Error(`bbot exited with code ${code}`);

      // 3. Diff against previous snapshot + generate alerts
      await this.diffAndAlert(worldId, moduleId, emit);

      return { moduleType: this.type, success: true, nodesAdded };
    } catch (error: any) {
      return { moduleType: this.type, success: false, nodesAdded: 0, error: error.message };
    }
  }

  private async diffAndAlert(
    worldId: string, moduleId: string, emit: ModuleEmitFn,
  ): Promise<void> {
    // Compare current entity set against previous OffchainScanSnapshot
    // For each security-relevant change:
    //   - Create TrackedFinding via TrackedFinding.create({...})
    //   - Emit alert via emitProgress(`world:${worldId}`, 'offchain:alert', {...})
  }
}
```

#### 7.2.4 Module Registration

```typescript
// src/sentry-worlds/modules/registry.ts — extend existing BUILDING_MODULES
export const BUILDING_MODULES: Record<BuildingModuleType, WorldBuildingModule<any>> = {
  [BuildingModuleType.ContractGraph]: new ContractGraphModule(),
  [BuildingModuleType.BbotDiscovery]: new BbotDiscoveryModule(),
  [BuildingModuleType.OffchainWeeklyScan]: new OffchainWeeklyScanModule(), // new
};
```

#### 7.2.5 Orchestration Service (following `WorldOrchestrationService` pattern)

```typescript
// src/offchain/OffchainOrchestrationService.ts (excerpt)
import { ModuleRecord } from '../db/models/ModuleRecord.js'
import { ModulePhase, ModuleStatus } from '../sentry-worlds/ModuleRecordService.js'
import { offchainTasks } from './tasks/offchainTasks.js'
import { BUILDING_MODULES } from '../sentry-worlds/modules/registry.js'
import { BuildingModuleType } from '../sentry-worlds/models/Module.js'
import { emitProgress } from '../task-queue/queue/progress.js'

export class OffchainOrchestrationService {
  async seedWeeklyScans(worldId?: string): Promise<void> {
    // Query active Worlds with offchainStatus='active'
    const worlds = worldId
      ? [await World.findById(worldId)]
      : await World.findByOffchainStatus('active');

    for (const world of worlds) {
      // Create ModuleRecord — same pattern as WorldOrchestrationService.startBuild()
      const record = await ModuleRecord.create({
        worldId: world.id,
        phase: ModulePhase.Build,
        moduleType: BuildingModuleType.OffchainWeeklyScan,
        status: ModuleStatus.Queued,
        recordData: {
          domains: world.domains,
        },
      });

      // Enqueue via .applyAsync() — same as WorldOrchestrationService.enqueueReadyModules()
      await offchainTasks.executeWeeklyScan.applyAsync(
        { worldId: world.id, moduleId: record.id },
        { jobId: `offchain-weekly:${world.id}:${record.id}` },
      );
    }
  }

  async executeWeeklyScan(
    worldId: string, moduleId: string, emit: typeof emitProgress,
  ): Promise<void> {
    // Same lifecycle as WorldOrchestrationService.executeBuildingModule()
    const record = await ModuleRecord.findById(moduleId);
    if (!record || record.status !== ModuleStatus.Queued) return;

    await ModuleRecord.update(moduleId, {
      status: ModuleStatus.Running, startedAt: new Date(),
    });

    const module = BUILDING_MODULES[BuildingModuleType.OffchainWeeklyScan];
    const result = await module.run(worldId, moduleId, record.recordData, emit);

    await ModuleRecord.update(moduleId, {
      status: result.success ? ModuleStatus.Completed : ModuleStatus.Failed,
      completedAt: new Date(),
      ...(result.error ? { error: result.error } : {}),
    });
  }
}
```

### 7.3 Execution Flow

The weekly scan follows the exact same lifecycle as Sentry's existing build modules (`executeBuildModule` in `WorldOrchestrationService`):

```
EventBridge Scheduler (Sunday 00:00 UTC)
  │
  │ SQS message → FAST_QUEUE targeting OffchainTasks.seedWeeklyScans
  ▼
┌─────────────────────────────────────────────────────────────────────┐
│  seedWeeklyScans  (@asyncTask FAST_QUEUE)                           │
│                                                                     │
│  1. Query World table: offchainStatus = 'active'                    │
│  2. For each World:                                                 │
│     a. ModuleRecord.create({                                        │
│          worldId, phase: 'build',                                   │
│          moduleType: 'OffchainWeeklyScan',                          │
│          status: 'queued',                                          │
│          recordData: { domains, orgName, githubOrgs }               │
│        })                                                           │
│     b. offchainTasks.executeWeeklyScan.applyAsync(                  │
│          { worldId, moduleId },                                     │
│          { jobId: `offchain-weekly:${worldId}:${moduleId}` }        │
│        )                                                            │
│        → sends SQS message to HEAVY_OFFCHAIN_QUEUE                  │
└─────────────────────────────────────────────────────────────────────┘
                         │ SQS messages
                         ▼
┌─────────────────────────────────────────────────────────────────────┐
│  executeWeeklyScan  (@asyncTask HEAVY_OFFCHAIN_QUEUE, ACK_IMMEDIATE)│
│  (one task per World, max 5 concurrent via queue concurrency)       │
│                                                                     │
│  1. ModuleRecord.findById(moduleId) → verify status is 'queued'     │
│  2. ModuleRecord.update(moduleId, { status: 'running' })            │
│  3. BUILDING_MODULES['OffchainWeeklyScan'].run(                     │
│       worldId, moduleId, record.recordData, emitProgress            │
│     )                                                               │
│     Inside OffchainWeeklyScanModule.run():                          │
│       a. spawn('bbot', ['-t', domains, '-p', 'all-but-intense-http',│
│          '--json', '-y', '-c', 'api_keys...'])                      │
│       b. Stream JSONL → mapBbotEventToEntity() per line             │
│       c. emitProgress(`world:${worldId}`, 'offchain:entityDiscovered│
│          ', {...}) per entity                                        │
│       d. Map VULNERABILITY/PASSWORD events → TrackedFinding.create()│
│       e. Diff against previous OffchainScanSnapshot                 │
│       f. Persist snapshot + emit alerts via emitProgress()           │
│  4. ModuleRecord.update(moduleId, { status: 'completed'|'failed' }) │
└─────────────────────────────────────────────────────────────────────┘
```

> **Key**: this is exactly how `WorldOrchestrationService.executeBuildingModule()` works today — find the module in `BUILDING_MODULES`, check the `ModuleRecord` status, call `module.run()`, update the record. The only new element is `HEAVY_OFFCHAIN_QUEUE`.

### 7.4 bbot Template: `all-but-intense-http.yaml`

The weekly scan should call bbot with:

```bash
bbot -t "<domains>" -p all-but-intense-http --json -y
```

Exact module membership comes from bbot's maintained template; we should not duplicate or hardcode the full list in this RFC.

Summary of what the template typically covers:

| Capability Area | Typical Modules from Template | Primary Output |
|-----------------|-------------------------------|----------------|
| Passive subdomain discovery | `crt`, `certspotter`, `otx`, `rapiddns` | DomainNode |
| DNS enrichment | `dnsresolve`, `dnscommonsrv`, `baddns` | DomainNode DNS/security attributes |
| HTTP probing/fingerprinting | `httpx`, `wafw00f`, `retirejs` | URLObject + web metadata |
| NetworkService/TLS discovery | `naabu`, `fingerprintx`, `sslcert` | NetworkServiceNode + cert attributes |
| Cloud/resource discovery | `bucket_*`, `azure_*` | CloudResourceNode |
| Code/repo discovery | `github_*`, `code_repository` | CodeRepositoryNode |
| Identity/leak discovery | `hunterio`, `leaklookup` | EmailAddress, TrackedFinding (secrets) |

### 7.5 Credentials & Secrets Management

Credentials follow the exact same pattern used by all existing Sentry services — environment variables resolved at deploy time, no custom secrets store:

 **Environment variables**: API keys are injected via `process.env` at deployment, the same way Sentry already handles `DATABASE_URL`, `CLAUDE_CODE_OAUTH_TOKEN_POOL`, SQS endpoints, etc. Workers running on `HEAVY_OFFCHAIN_QUEUE` inherit the same env context as `FAST_QUEUE`/`SLOW_QUEUE` workers.
 **AWS credential chain**: Workers inherit IAM roles for S3 and SQS access automatically — same mechanism as all existing Sentry workers (the `SQSClient` in `src/task-queue/queue/connection.ts` already uses the default credential chain via `process.env.AWS_REGION`).
 **bbot API key injection**: Environment variables are mapped to bbot `-c` flags at spawn time:

```typescript
// Mapping env vars → bbot -c config flags
const BBOT_API_KEY_MAP: Record<string, string> = {
  SHODAN_API_KEY:       'modules.shodan_dns.api_key',
  VIRUSTOTAL_API_KEY:   'modules.virustotal.api_key',
  GITHUB_TOKEN:         'modules.github_org.api_key',
  CENSYS_API_ID:        'modules.censys.api_id',
  CENSYS_API_SECRET:    'modules.censys.api_secret',
  HUNTERIO_API_KEY:     'modules.hunterio.api_key',
};

// In OffchainWeeklyScanModule.run():
for (const [envVar, bbotKey] of Object.entries(BBOT_API_KEY_MAP)) {
  if (process.env[envVar]) args.push('-c', `${bbotKey}=${process.env[envVar]}`);
}
```

 **Rotation**: Centralized in deployment config (ECS task definition / Terraform) — no per-client changes.
 Never persist plaintext secrets in DB.

### 7.6 Weekly Alert Emission (When + How)

Weekly alerts use **Sentry's existing alert pipeline** — the same `emitProgress()` → Postgres NOTIFY → Socket.IO route used by `ContractGraphModule` and `BbotDiscoveryModule` today.

 **When alerts are emitted**:
  - New critical/high findings discovered in weekly scan.
  - Security-relevant changes against previous weekly snapshot (new vulnerable asset, exposed secret, risky DNS/TLS changes).
  - Removals only when meaningful for security posture.
 **How alerts are emitted** (concrete Sentry calls):
  1. **Security findings** → `TrackedFinding.create({ worldId, severity, title, description, recommendation, poc, location })` — same model used by existing fuzzing/audit findings.
  2. **Real-time UI notifications** → `await emitProgress(`world:${worldId}`, 'offchain:alert', { worldId, alertType, severity, entity, changes })` — this calls `pg_notify('task_progress', ...)` (see `src/task-queue/queue/progress.ts`), and the Socket.IO listener in the API server forwards it to the `world:${worldId}` room.
  3. **Slack webhook** (optional) → implementation deferred; no `World.offchainAlertWebhookUrl` field exists in the current model.
 **Slack policy**:
  - `critical`/`high`: immediate message.
  - `medium`/`low`/`info`: grouped digest (single message per run).
 **Dedup policy**:
  - Fingerprint: `worldId + entityType + identityKey + changeHash + monitorType`.
  - Suppress repeats for 24h unless severity increases.

### 7.7 Multi-Client Weekly Launch Plan

When several clients (Worlds) are configured, weekly scans start from a single global kickoff:

 **Kickoff time**: every Sunday at `00:00 UTC` (configurable per World via `offchainWeeklyScanDay`/`offchainWeeklyScanTime`).
 **Concurrency**: `HEAVY_OFFCHAIN_QUEUE.concurrency = 5` — the SQS worker polling loop in `src/task-queue/worker/index.ts` tracks `inFlight` promises and only pulls new messages when `inFlight.size < concurrency`. At most 5 bbot processes run in parallel across all Worlds.
 **Dispatch rule**:
  - `seedWeeklyScans` (FAST_QUEUE) queries all active Worlds and calls `offchainTasks.executeWeeklyScan.applyAsync()` per World — this sends one `SendMessageCommand` to SQS per World (see `src/task-queue/queue/decorator.ts`).
  - SQS + Sentry worker infrastructure handles ordering and concurrency natively.
  - No custom queue table needed — SQS is the queue.
 **Retry/failure policy**:
  - `HEAVY_OFFCHAIN_QUEUE` uses `ACK_IMMEDIATE` — the message is deleted before the handler runs. If the handler fails, the `ModuleRecord` is marked `failed` and an operational alert is emitted via `emitProgress()`.
  - For automatic retry, the seeder can check for `ModuleRecord.status = 'failed'` on the next run and re-enqueue.
  - Critical operational failures (e.g. bbot binary missing, DB unreachable) → `emitProgress(`ops:alerts`, 'ops:offchainFailure', { worldId, error })`.

--

## 8. Real-Time Continuous Monitoring

### 8.1 Overview

Real-time monitors are lightweight, long-lived processes that detect deltas on critical infrastructure and social signals.

Each monitor is implemented as a **monitoring plugin** using Sentry's existing monitoring plugin system (branch `202604_UpdateMonitors`). This system already powers on-chain monitors (`contract-event-monitor`, `safe-monitor`) and provides a purpose-built framework for long-lived monitoring: a dedicated `MONITOR_QUEUE` (SQS), a `MonitorRuntimeHost` that manages monitor lifecycles with Postgres advisory locks and heartbeats, a `SourceManager` pattern for persistent polling/streaming, and a `MonitorHandler` pattern for event processing. Alerts are emitted via `MonitorEventService` (which persists events to the `MonitorEvent` table) and `MonitorAction` triggers (webhooks, Slack, etc.). Monitor state is persisted in `Monitor.recordData` per-monitor and `ModuleRecord.recordData` per-source.

**Why the monitoring plugin system instead of bare `@asyncTask(FAST_QUEUE)`**:

 **Dedicated queue**: `MONITOR_QUEUE` has concurrency 10 and does not compete with build/work tasks on `FAST_QUEUE` (concurrency 3) or `SLOW_QUEUE` (concurrency 1).
 **Long-lived processes**: `MonitorRuntimeHost` keeps a worker slot occupied indefinitely — the `SourceManager` runs a persistent polling loop or streaming connection. No need for repeated EventBridge → SQS cron scheduling.
 **Hot reconfiguration**: Postgres NOTIFY control plane (`control.ts`) lets monitors be created/updated/paused/resumed/deleted without restarting the host process.
 **Deduplication**: `NormalizedMonitorEvent.dedupeKey` provides built-in event deduplication at the persistence layer.
 **Advisory locks**: `pg_try_advisory_lock` prevents the same monitor from running on multiple workers simultaneously.
 **Heartbeats**: 10s heartbeat writes to `ModuleRecord.heartbeatAt` enable stale-monitor detection and recovery.
 **Existing CRUD API**: `WorldMonitorService` already provides create/update/pause/resume/delete for monitors — offchain monitors slot in with zero new API surface.

### 8.2 Infrastructure — Sentry Monitoring Plugin System

Real-time monitoring is built on Sentry's existing monitoring plugin system (`src/monitoring/`). The key components are:

 **`MONITOR_QUEUE`** (`src/task-queue/queue/queues.ts`): dedicated SQS queue for monitor runtimes.
 **`MonitorModuleDefinition`** (`src/monitoring/modules/registry.ts`): plugin registration interface.
 **`MonitorRuntimeHost`** (`src/monitoring/MonitorRuntimeHost.ts`): long-lived host that manages `SourceManager` lifecycles.
 **`MonitorHandler<TEvent>`** / **`SourceManager<TEvent>`** (`src/monitoring/types.ts`): per-monitor event handler and per-source lifecycle manager.
 **`WorldMonitorService`** (`src/monitoring/WorldMonitorService.ts`): CRUD API that creates `ModuleRecord` (phase: Monitor) and dispatches to `MONITOR_QUEUE`.
 **`MonitorEvent`** / **`MonitorAction`** (`src/db/models/monitoring/`): persisted events and triggered actions (webhooks, Slack, etc.).

#### 8.2.1 MONITOR_QUEUE Definition

The `MONITOR_QUEUE` is already defined on the `202604_UpdateMonitors` branch alongside the existing queues:

```typescript
// src/task-queue/queue/queues.ts — already exists on 202604_UpdateMonitors
export const MONITOR_QUEUE: QueueDefinition = {
  name: process.env.MONITOR_QUEUE_NAME || 'monitoring',
  concurrency: parseInt(process.env.MONITOR_QUEUE_CONCURRENCY || '10', 10),
  ackMode: ACK_IMMEDIATE,  // monitors are long-lived; worker owns lifecycle
};

export const ALL_QUEUES: QueueDefinition[] = [
  FAST_QUEUE,
  SLOW_QUEUE,
  CONVERSATION_QUEUE,
  MONITOR_QUEUE,
];
```

#### 8.2.2 New MonitorModuleType Entries for Offchain Monitors

We extend the existing `MONITOR_MODULES` registry with new offchain monitor types. Each offchain monitor follows the same `MonitorModuleDefinition` interface used by the existing `contract-event-monitor` and `safe-monitor`:

```typescript
// src/monitoring/modules/registry.ts — additions
export const MONITOR_MODULE_TYPES = [
  'contract-event-monitor',
  'safe-monitor',
  // --- NEW offchain monitor types ---
  'offchain-dns-monitor',
  'offchain-ct-monitor',
  'offchain-whois-monitor',
  'offchain-cert-expiry-monitor',
  'offchain-subdomain-monitor',
  'offchain-reputation-monitor',
  'offchain-leak-monitor',
  'offchain-github-monitor',
  'offchain-phishing-monitor',
  'offchain-discord-monitor',
  'offchain-x-monitor',
] as const;

// Example registration for DNS monitor:
export const OFFCHAIN_DNS_MONITOR_TYPE: MonitorModuleType = 'offchain-dns-monitor';

MONITOR_MODULES[OFFCHAIN_DNS_MONITOR_TYPE] = {
  type: OFFCHAIN_DNS_MONITOR_TYPE,
  runtimeMode: MonitorRuntimeMode.Active,  // long-lived polling loop
  deriveSourceKey(data: OffchainDnsMonitorRecordData) {
    // One source per World — all DNS monitors for a World share a SourceManager
    return `offchain-dns:${data.worldId}`;
  },
  buildSourceRecordData(data: OffchainDnsMonitorRecordData) {
    return {
      monitorType: OFFCHAIN_DNS_MONITOR_TYPE,
      sourceType: MonitorSourceType.OffchainDns,
      sourceKey: `offchain-dns:${data.worldId}`,
      worldId: data.worldId,
    };
  },
  createMonitor(sourceRecord: ModuleRecord, record: Monitor): MonitorHandler<DnsChangeEvent> {
    return new OffchainDnsMonitorHandler(sourceRecord, record);
  },
  createSourceManager(sourceRecord: ModuleRecord): SourceManager<DnsChangeEvent> {
    return new OffchainDnsSourceManager(sourceRecord);
  },
};

// Same pattern for each offchain monitor type:
// MONITOR_MODULES['offchain-ct-monitor'] = { ... createSourceManager: OffchainCtSourceManager, ... }
// MONITOR_MODULES['offchain-whois-monitor'] = { ... }
// etc.
```

#### 8.2.3 SourceManager & MonitorHandler Patterns

Each offchain monitor implements two interfaces from `src/monitoring/types.ts`:

```typescript
// SourceManager<TEvent> — one per source key, manages the polling loop
interface SourceManager<TEvent> {
  readonly sourceKey: string;
  start(): Promise<void>;     // begins the long-lived polling loop
  stop(): Promise<void>;      // gracefully shuts down
  syncMonitors(monitors: MonitorHandler<TEvent>[], sourceRecord: ModuleRecord): Promise<void>;
    // hot-reload: update the set of active handlers without restarting the loop
}

// MonitorHandler<TEvent> — one per Monitor row, processes individual events
interface MonitorHandler<TEvent> {
  readonly monitorId: string;
  readonly sourceKey: string;
  readonly moduleType: string;
  readonly sourceRecord: ModuleRecord;
  readonly record: Monitor;
  readonly recordData: any;
  handleEvent(event: TEvent): Promise<void>;
    // called by SourceManager when a relevant event occurs
    // persists to MonitorEvent via monitorEventService.createOrGetExisting()
}
```

#### 8.2.4 Monitor Lifecycle

The lifecycle follows the existing pattern used by `contract-event-monitor` and `safe-monitor`:

```
User enables offchain monitoring for World
  → WorldMonitorService.createAndStartMonitor(worldId, 'offchain-dns-monitor', recordData)
    → Creates ModuleRecord (phase: Monitor, status: Running)
    → Creates Monitor row (per-monitor config + state in recordData)
    → worldTasks.executeMonitorModule.applyAsync({ moduleId }) → MONITOR_QUEUE (SQS)

Worker picks up SQS message from MONITOR_QUEUE
  → MonitorRuntimeModule.run(moduleId)
    → monitorRuntimeHost.startMonitor(moduleId)
      → Acquires pg_advisory_lock (prevents duplicate hosting)
      → MONITOR_MODULES['offchain-dns-monitor'].createSourceManager(sourceRecord)
      → MONITOR_MODULES['offchain-dns-monitor'].createMonitor(sourceRecord, monitorRow)
      → sourceManager.syncMonitors([handler], sourceRecord)
      → sourceManager.start()  ← begins long-lived polling loop
      → Starts 10s heartbeat timer → ModuleRecord.heartbeatAt
      → Subscribes to Postgres NOTIFY channel for control events
      → Blocks on stopPromise (worker slot stays occupied)

During runtime:
  → SourceManager polls DNS/CT/WHOIS/etc. on its cadence
  → On change detected → handler.handleEvent(event)
    → monitorEventService.createOrGetExisting({ dedupeKey, title, severity, ... })
    → MonitorAction triggers fire (webhook, Slack, etc.)

Control events (via Postgres NOTIFY):
  → MonitorControlAction.Updated → hot-reload handlers (syncMonitors)
  → MonitorControlAction.Deleted → stop SourceManager + release lock
  → MonitorControlAction.Resumed → restart from latest checkpoint
```

### 8.2.5 How Each Monitor Loads Client Data

Each `SourceManager` receives its `ModuleRecord` (which includes `worldId`) and queries the `World` entity for the fields it needs. Credentials come from `process.env` (same as all Sentry services). Per-monitor state is stored in `Monitor.recordData`; per-source state is in `ModuleRecord.recordData`.

```typescript
// Example: OffchainDnsSourceManager polling loop
async pollOnce() {
  const world = await World.findById(this.sourceRecord.worldId);
  const domains = world.domains;
  const excluded = new Set(world.offchainExcludedDomains ?? []);
  for (const domain of domains) {
    if (excluded.has(domain)) continue;
    const current = await resolveDnsRecords(domain);
    // For each active handler, call handler.handleEvent({ domain, records: current })
    for (const handler of this.handlers) {
      await handler.handleEvent({ domain, records: current });
    }
  }
}
```

Monitor input mapping:

| Monitor Plugin Type | World Fields Used |
|---------------------|-------------------|
| `offchain-dns-monitor` | `domains`, `offchainExcludedDomains` |
| `offchain-ct-monitor` | `domains` |
| `offchain-whois-monitor` | `domains` |
| `offchain-cert-expiry-monitor` | discovered `URLObject` / `NetworkServiceNode` records |
| `offchain-subdomain-monitor` | `domains`, `offchainExcludedDomains` |
| `offchain-reputation-monitor` | discovered Domain/IP nodes (+ `offchainExcludedIps`) |
| `offchain-leak-monitor` | `domains` |
| `offchain-github-monitor` | deferred — no dedicated World field implemented |
| `offchain-phishing-monitor` | `domains` |
| `offchain-discord-monitor` | deferred — no dedicated World field implemented |
| `offchain-x-monitor` | deferred — no dedicated World field implemented |

### 8.3 Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│              WorldMonitorService (existing CRUD API)              │
│  createAndStartMonitor(worldId, 'offchain-dns-monitor', data)    │
│  → Creates ModuleRecord (phase: Monitor, status: Running)        │
│  → Creates Monitor row                                           │
│  → worldTasks.executeMonitorModule.applyAsync({ moduleId })      │
└───────────────────────────┬──────────────────────────────────────┘
                            │  SQS message to MONITOR_QUEUE
                            │  body: { moduleId: '...' }
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│                MONITOR_QUEUE (dedicated SQS queue)                │
│           concurrency: 10, ackMode: ACK_IMMEDIATE                │
│           name: process.env.MONITOR_QUEUE_NAME || 'monitoring'   │
└───────────────────────────┬──────────────────────────────────────┘
                            │
                            ▼
┌──────────────────────────────────────────────────────────────────┐
│  MonitorRuntimeModule.run(moduleId)                               │
│  → monitorRuntimeHost.startMonitor(moduleId)                     │
│                                                                   │
│  1. Acquire pg_advisory_lock(moduleId) — prevent duplicates      │
│  2. MONITOR_MODULES['offchain-dns-monitor']                      │
│     .createSourceManager(sourceRecord) → OffchainDnsSourceManager│
│     .createMonitor(sourceRecord, monitorRow) → handler           │
│  3. sourceManager.syncMonitors([handler], sourceRecord)          │
│  4. sourceManager.start() — begins long-lived polling loop       │
│  5. Start 10s heartbeat → ModuleRecord.heartbeatAt               │
│  6. Subscribe to Postgres NOTIFY channel for control events      │
│  7. Block on stopPromise (worker slot stays occupied)            │
└───────────────────────────┬──────────────────────────────────────┘
                            │
              ┌─────────────┼──────────────────┐
              ▼             ▼                  ▼
     ┌──────────────┐ ┌─────────────┐ ┌───────────────┐
     │MonitorEvent   │ │Monitor      │ │MonitorAction  │
     │(persisted,    │ │.recordData  │ │(webhook/Slack │
     │ deduplicated) │ │(checkpoint/ │ │ triggers)     │
     │ via dedupeKey │ │ last state) │ │               │
     └──────────────┘ └─────────────┘ └───────────────┘

Control Plane (hot reconfiguration without restart):
┌──────────────────────────────────────────────────────────────────┐
│  Postgres NOTIFY → MonitorControlListener                        │
│  MonitorControlAction.Created  → add handler to SourceManager    │
│  MonitorControlAction.Updated  → syncMonitors (hot-reload)       │
│  MonitorControlAction.Deleted  → stop SourceManager + release    │
│  MonitorControlAction.Resumed  → restart from checkpoint         │
└──────────────────────────────────────────────────────────────────┘
```

> **Key**: offchain monitors use the **exact same infrastructure** as the existing `contract-event-monitor` and `safe-monitor`. The only new code is the `SourceManager` and `MonitorHandler` implementations for each offchain monitor type, plus their registration in `MONITOR_MODULES`. No new queues, no new worker types, no custom schedulers.

### 8.4 Real-Time Monitor Specifications

--

#### 8.4.1 DNS Record Monitor

**Frequency**: Every 30 seconds
**Input**: All known DomainNode FQDNs from WorldGraph
**Method**: Direct DNS resolution (UDP queries via `dns.resolve()` / `dig`)

| What is monitored | DomainNode Attribute | Alert Trigger |
|--------------------|---------------------|---------------|
| A records | `dns_a` | IP address added/removed |
| AAAA records | `dns_aaaa` | IPv6 address added/removed |
| CNAME records | `dns_cname` | CNAME target changed |
| MX records | `dns_mx` | Mail server changed |
| NS records | `dns_ns` | Nameserver changed |
| TXT records | `dns_txt` | TXT record changed (SPF/DMARC/DKIM) |
| SOA records | `dns_soa` | SOA serial changed |
| CAA records | `dns_caa` | CAA policy changed |

**Implementation** (implements `MonitorHandler<DnsChangeEvent>` + `SourceManager<DnsChangeEvent>` from Section 8.2.3):

```typescript
// src/monitoring/providers/offchainDns.ts

// ---------- Event type ----------
interface DnsChangeEvent {
  domain: string;
  recordType: string;
  previous: string[];
  current: string[];
}

// ---------- MonitorHandler ----------
export class OffchainDnsMonitorHandler implements MonitorHandler<DnsChangeEvent> {
  readonly monitorId: string;
  readonly sourceKey: string;
  readonly moduleType = 'offchain-dns-monitor';
  readonly recordData: OffchainDnsMonitorRecordData;

  constructor(
    public readonly sourceRecord: ModuleRecord,
    public readonly record: Monitor,
  ) {
    this.monitorId = record.id;
    this.recordData = record.recordData as OffchainDnsMonitorRecordData;
    this.sourceKey = `offchain-dns:${sourceRecord.worldId}`;
  }

  async handleEvent(event: DnsChangeEvent): Promise<void> {
    const diff = diffDnsRecords(event);
    if (!diff.hasChanges) return;

    const severity = classifyDnsSeverity(diff);
    const dedupeKey = `dns:${event.domain}:${event.recordType}:${hashChanges(diff)}`;

    // Persist alert via MonitorEventService (built-in deduplication via dedupeKey)
    await monitorEventService.createOrGetExisting({
      worldId: this.sourceRecord.worldId,
      monitorId: this.record.id,
      severity,
      title: `DNS ${event.recordType} change: ${event.domain}`,
      description: JSON.stringify(diff.changes),
      dedupeKey,
      sourceEventId: `${event.domain}:${event.recordType}:${Date.now()}`,
      metadata: {
        domain: event.domain,
        recordType: event.recordType,
        previous: event.previous,
        current: event.current,
      },
      occurredAt: new Date(),
    });

    // Update Monitor.recordData checkpoint
    await monitorService.update(this.record.id, {
      recordData: {
        ...this.recordData,
        domainStates: {
          ...this.recordData.domainStates,
          [event.domain]: event.current,
        },
        lastCheckedAt: new Date().toISOString(),
      },
    } as any);

    // Create TrackedFinding for high-severity DNS changes (NS hijack, etc.)
    if (severity === 'high' || severity === 'critical') {
      await TrackedFinding.create({
        worldId: this.sourceRecord.worldId,
        severity,
        title: `DNS change detected: ${event.domain}`,
        description: JSON.stringify(diff.changes),
        valid: true,
      });
    }
  }
}

// ---------- SourceManager ----------
export class OffchainDnsSourceManager implements SourceManager<DnsChangeEvent> {
  readonly sourceKey: string;
  private handlers: OffchainDnsMonitorHandler[] = [];
  private running = false;
  private pollTimer: NodeJS.Timeout | undefined;

  // Polling cadence — configurable per source
  private readonly pollIntervalMs = 30_000; // 30 seconds

  constructor(private readonly sourceRecord: ModuleRecord) {
    this.sourceKey = `offchain-dns:${sourceRecord.worldId}`;
  }

  async syncMonitors(monitors: MonitorHandler<DnsChangeEvent>[], _sourceRecord: ModuleRecord) {
    this.handlers = monitors as OffchainDnsMonitorHandler[];
  }

  async start(): Promise<void> {
    this.running = true;
    this.schedulePoll();
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.pollTimer) clearTimeout(this.pollTimer);
  }

  private schedulePoll() {
    if (!this.running) return;
    this.pollTimer = setTimeout(async () => {
      await this.pollOnce();
      this.schedulePoll();
    }, this.pollIntervalMs);
  }

  private async pollOnce() {
    const world = await World.findById(this.sourceRecord.worldId);
    const domains = world.domains;
    const excluded = new Set(world.offchainExcludedDomains ?? []);

    for (const domain of domains) {
      if (excluded.has(domain)) continue;
      const current = await resolveDnsRecords(domain);

      // Dispatch to all active handlers
      for (const handler of this.handlers) {
        const previous = handler.recordData.domainStates?.[domain];
        if (!previous) continue; // first run — baseline only
        for (const [recordType, values] of Object.entries(current)) {
          await handler.handleEvent({
            domain,
            recordType,
            previous: previous[recordType] ?? [],
            current: values,
          });
        }
      }
    }
  }
}
```

--

#### 8.4.2 Certificate Transparency Monitor

**Frequency**: Every 30 seconds
**Input**: Root domains from World's `domains`
**Method**: CRT.sh API + Certspotter API polling for new certificates

| What is monitored | Entity Affected | Alert Trigger |
|--------------------|----------------|---------------|
| New certificates issued | DomainNode (new subdomains in SAN) | New subdomain discovered via CT |
| Certificate details | DomainNode.certificate | New cert issued for monitored domain |
| SAN entries | DomainNode creation | Previously unknown FQDNs in certificate SAN |

**Implementation** (implements `MonitorHandler<CtCertEvent>` + `SourceManager<CtCertEvent>`):

```typescript
// src/monitoring/providers/offchainCt.ts

interface CtCertEvent {
  domain: string;
  sanDomains: string[];
  certSerial: string;
  issuer: string;
}

export class OffchainCtMonitorHandler implements MonitorHandler<CtCertEvent> {
  readonly monitorId: string;
  readonly sourceKey: string;
  readonly moduleType = 'offchain-ct-monitor';
  readonly recordData: OffchainCtMonitorRecordData;

  constructor(
    public readonly sourceRecord: ModuleRecord,
    public readonly record: Monitor,
  ) {
    this.monitorId = record.id;
    this.recordData = record.recordData as OffchainCtMonitorRecordData;
    this.sourceKey = `offchain-ct:${sourceRecord.worldId}`;
  }

  async handleEvent(event: CtCertEvent): Promise<void> {
    const world = await World.findById(this.sourceRecord.worldId);
    const rootDomains = world.domains;

    for (const san of event.sanDomains) {
      if (!isInScope(san, rootDomains)) continue;
      if (await domainNodeExists(world.id, san)) continue;

      // Create new DomainNode + trigger DNS resolution
      await createDomainNodeFromCT(world.id, san, event);

      // Persist alert via MonitorEventService
      await monitorEventService.createOrGetExisting({
        worldId: this.sourceRecord.worldId,
        monitorId: this.record.id,
        severity: 'medium',
        title: `New subdomain via CT: ${san}`,
        dedupeKey: `ct:${san}:${event.certSerial}`,
        sourceEventId: event.certSerial,
        metadata: {
          domain: san,
          certSerial: event.certSerial,
          issuer: event.issuer,
          sanDomains: event.sanDomains,
        },
        occurredAt: new Date(),
      });

      // Enqueue expansion scan for the new domain via HEAVY_OFFCHAIN_QUEUE
      await offchainTasks.executeExpansionScan.applyAsync({
        worldId: world.id,
        moduleId: this.sourceRecord.id,
        entityType: 'domain',
        identityKey: san,
      });
    }

    // Update checkpoint
    await monitorService.update(this.record.id, {
      recordData: {
        ...this.recordData,
        lastCheckTime: new Date().toISOString(),
      },
    } as any);
  }
}

export class OffchainCtSourceManager implements SourceManager<CtCertEvent> {
  readonly sourceKey: string;
  private handlers: OffchainCtMonitorHandler[] = [];
  private running = false;
  private pollTimer: NodeJS.Timeout | undefined;
  private readonly pollIntervalMs = 30_000; // 30 seconds

  constructor(private readonly sourceRecord: ModuleRecord) {
    this.sourceKey = `offchain-ct:${sourceRecord.worldId}`;
  }

  async syncMonitors(monitors: MonitorHandler<CtCertEvent>[], _sourceRecord: ModuleRecord) {
    this.handlers = monitors as OffchainCtMonitorHandler[];
  }

  async start(): Promise<void> {
    this.running = true;
    this.schedulePoll();
  }

  async stop(): Promise<void> {
    this.running = false;
    if (this.pollTimer) clearTimeout(this.pollTimer);
  }

  private schedulePoll() {
    if (!this.running) return;
    this.pollTimer = setTimeout(async () => {
      await this.pollOnce();
      this.schedulePoll();
    }, this.pollIntervalMs);
  }

  private async pollOnce() {
    const world = await World.findById(this.sourceRecord.worldId);
    const rootDomains = world.domains;
    const lastCheckTime = this.handlers[0]?.recordData?.lastCheckTime
      ? new Date(this.handlers[0].recordData.lastCheckTime)
      : new Date(Date.now() - 60_000);

    for (const domain of rootDomains) {
      const newCerts = await queryCrtSh(domain, lastCheckTime);
      for (const cert of newCerts) {
        const event: CtCertEvent = {
          domain,
          sanDomains: cert.san_domains,
          certSerial: cert.serial,
          issuer: cert.issuer,
        };
        for (const handler of this.handlers) {
          await handler.handleEvent(event);
        }
      }
    }
  }
}
```

--

#### 8.4.3 WHOIS Expiry Monitor

**Frequency**: Every 1 hour (3,600 seconds)
**Input**: Root domains (registered domains, not subdomains)
**Method**: WHOIS lookup via `whois` command or RDAP API

| What is monitored | DomainNode Attribute | Alert Trigger |
|--------------------|---------------------|---------------|
| Expiration date | `expiration_date` | Domain expires within 30/14/7/1 days |
| Registrar | `registrar` | Registrar changed |
| WHOIS status | `whois_status` | Status code changed (e.g. `pendingDelete`) |
| Nameservers | `dns_ns` | Nameserver changed (cross-validated with DNS monitor) |
| DNSSEC | `dnssec` | DNSSEC enabled/disabled |

--

#### 8.4.4 TLS Certificate Expiry Monitor

**Frequency**: Every 1 hour
**Input**: All known URL endpoints (HTTPS) and NetworkService endpoints with TLS
**Method**: TLS handshake to retrieve live certificate

| What is monitored | Attribute | Alert Trigger |
|--------------------|----------|---------------|
| Certificate `not_after` | `certificate.not_after` | Cert expires within 30/14/7/1 days |
| Certificate issuer | `certificate.issuer_cn` | Issuer changed |
| Certificate SAN | `certificate.san_domains` | SAN entries changed |
| Self-signed status | `certificate.is_self_signed` | Changed to self-signed |
| Key algorithm/size | `certificate.key_algorithm`, `key_size` | Downgraded |

--

#### 8.4.5 Subdomain Discovery Monitor (Passive)

**Frequency**: Every 1 hour
**Input**: Root domains
**Method**: Passive API calls to free OSINT sources (no API key required)

| API Source | bbot Module Equivalent | Rate |
|------------|----------------------|------|
| CRT.sh | `crt` | Every 1h |
| Certspotter | `certspotter` | Every 1h |
| AlienVault OTX | `otx` | Every 1h |
| HackerTarget | `hackertarget` | Every 1h |
| RapidDNS | `rapiddns` | Every 1h |
| Digitorus | `digitorus` | Every 1h |
| Anubis DB | `anubisdb` | Every 1h |

**Detection**: Compare returned subdomain set against known DomainNodes. New subdomains trigger:

1. DomainNode creation (`is_resolved: false`, with `parent_domain_id` FK set)
2. Immediate DNS resolution (populate `dns_a`, `dns_aaaa`, etc.)
3. If resolved → create IPAddressNode + `resolves_to` edge
4. Alert: "New subdomain discovered"

--

#### 8.4.6 IP & Domain Reputation Monitor

**Frequency**: Every 1 hour
**Input**: All known IPAddressNodes and DomainNodes
**Method**: Query free reputation APIs for IP and domain reputation

| What is monitored | Entity Attribute | Alert Trigger |
|--------------------|------------------|---------------|
| IP blacklist status | `IPAddressNode.blacklisted`, `blacklist_sources` | IP added to/removed from blacklist |
| IP risk score | `IPAddressNode.risk_score` | Score increased by > 20 points |
| IP Tor/VPN/Proxy status | `IPAddressNode.is_tor`, `is_vpn`, `is_proxy` | Classification changed |
| Domain blacklist/reputation | `DomainNode` reputation metadata | Domain appears on/removed from blocklists |

--

#### 8.4.7 Leak & Breach Monitor

**Frequency**: Every 6 hours
**Input**: All known email addresses and domains
**Method**: Public LeakLookup checks only. Alert only when truly new leaks/breaches are detected versus stored state.

**Policy**:

 No paid APIs in real-time mode (`dehashed`, paid LeakLookup tiers, etc.).
 If public LeakLookup is unavailable or rate-limited, do not spam retries; run leak/breach checks in the weekly scan only (once per week).

| What is monitored | Entity | Alert Trigger |
|--------------------|--------|---------------|
| New breaches containing org emails | TrackedFinding + EmailAddress | Email found in new breach |
| New credential exposures | TrackedFinding | Password/hash for org email found |

--

#### 8.4.8 GitHub Activity Monitor

**Frequency**: Every 1 hour
**Input**: GitHub org slugs from config
**Method**: GitHub API (requires `github_token`)

| What is monitored | Entity | Alert Trigger |
|--------------------|--------|---------------|
| New public repositories | CodeRepositoryNode | New repo created |
| Repository visibility changes | CodeRepositoryNode.`is_public` | Repo changed to public |
| New workflow files | CodeRepositoryNode | CI/CD config changed |
| Secret scanning alerts | TrackedFinding | GitHub secret alert |

--

#### 8.4.9 Domain Phishing Monitor

**Frequency**: Every 1 hour
**Input**: Root domains
**Method**: dnstwist + CT + new-domain registration feeds for lookalike detection

| What is monitored | DomainNode Attribute | Alert Trigger |
|--------------------|---------------------|---------------|
| Similar domain registrations | `phishing_like_domains_history` | New lookalike domain registered |
| Confusable domains | — | Unicode/homoglyph domain detected |

--

#### 8.4.10 Discord Server Monitor (Sentiment + Compromise Detection)

**Frequency**: Every 1 minute (polling)
**Input**: integration-specific server/channel configuration (deferred — no dedicated World field is implemented)
**Method**: Discord API polling of configured servers/channels

**Optional constant mode**: use a dedicated always-on EC2 instance for websocket/gateway monitoring when near-instant event capture is required.

**Goal**: Detect suspicious behavior that may indicate account compromise (fake token sale, wallet-drain links, urgent money asks, malicious giveaways) and monitor sentiment shifts.

| What is monitored | Scope | Alert Trigger |
|--------------------|-------|---------------|
| Suspicious admin/mod messages | Official server channels | Messages matching compromise lexicon + risky links |
| Invite-link abuse/spam | Official server channels | Sudden burst of unknown invite links |
| Account behavior anomaly | High-trust roles | Posting pattern/time/language deviates from baseline |
| Sentiment drift | Project mention stream | Sharp negative sentiment spike vs baseline |

**Required**:

 `discord_bot_token`
 `discord_application_id`
 Bot invited to monitored servers with read-message permissions

--

#### 8.4.11 X Account Monitor (Sentiment + Account Takeover Detection)

**Frequency**: Every 1 minute (polling)
**Input**: integration-specific account configuration (deferred — no dedicated World field is implemented)
**Method**: X API recent-post polling + account profile delta checks

**Optional constant mode**: use a dedicated always-on EC2 instance for continuous stream consumption where API plan and use case require it.

**Goal**: Detect likely hacked accounts and high-risk impersonation/phishing campaigns quickly.

| What is monitored | Scope | Alert Trigger |
|--------------------|-------|---------------|
| Suspicious monetization/scam content | Official X accounts | Posts asking for money/wallet connect/airdrop urgency |
| Rapid posting anomaly | Official X accounts | Burst posting outside account baseline |
| Profile takeover signals | Official X accounts | Bio/name/url/avatar sudden change to suspicious content |
| Community sentiment shift | Replies/mentions | Spike in negative/security-warning sentiment |

**Required**:

 `x_bearer_token` (or equivalent app token)
 `x_api_key` + `x_api_secret` (depending on selected API tier)

--

#### 8.4.12 Additional Constant Monitors (Recommended)

| Monitor | Frequency | Why |
|---------|-----------|-----|
| Brand-new domain registration monitor | 15min | Catches freshly registered phishing lookalikes before heavy use |
| Certificate issuer anomaly monitor | 15min | Detects unexpected cert issuers that may indicate abuse/misissuance |
| Social impersonation handle monitor (X/Telegram/Discord) | 30min | Detects newly created lookalike handles quickly |

### 8.5 Real-Time Monitor Summary Table

| Monitor | Frequency | Data Source | Entity Types Updated | Requires API Key |
|---------|-----------|-------------|---------------------|-----------------|
| DNS Records | 30s | Direct DNS | DomainNode | No |
| CT Log | 30s | CRT.sh, Certspotter | DomainNode | No |
| WHOIS Expiry | 1h | WHOIS/RDAP | DomainNode | No |
| TLS Cert Expiry | 1h | TLS handshake | URLObject, NetworkServiceNode, DomainNode | No |
| Subdomain Discovery | 1h | OSINT APIs | DomainNode, IPAddressNode | No (enhanced with keys) |
| IP & Domain Reputation | 1h | Reputation APIs | IPAddressNode, DomainNode | Optional |
| Leak & Breach | 6h | Public LeakLookup | TrackedFinding, EmailAddress | No |
| GitHub Activity | 1h | GitHub API | CodeRepositoryNode, TrackedFinding | Yes |
| Phishing Domains | 15min | dnstwist + CT + registration feeds | DomainNode | No |
| Discord Server Sentiment/Compromise | 1min (poll) | Discord API | SocialProfileNode, Alert-only events | Yes |
| X Sentiment/Compromise | 1min (poll) | X API | SocialProfileNode, Alert-only events | Yes |

### 8.6 Real-Time Alert Emission (When + How)

Real-time alerts use the monitoring plugin system's existing alert pipeline: `MonitorEventService` (persists events with deduplication) + `MonitorAction` (triggers webhooks, Slack, etc.). This is the same pipeline used by `contract-event-monitor` and `safe-monitor`.

 **When alerts are emitted**:
  - First observation of a risky state (new blacklist hit, phishing domain found, suspicious social post/profile change).
  - Existing risky state gets worse (severity escalation).
  - Recovery events can be emitted as `info` if state returns to normal.
 **How alerts are emitted** (concrete Sentry calls inside each `MonitorHandler.handleEvent()`):
  1. **Persisted alert event** (with built-in deduplication):
     ```typescript
     // Inside handler.handleEvent(event):
     await monitorEventService.createOrGetExisting({
       worldId: this.sourceRecord.worldId,
       monitorId: this.record.id,
       severity: 'high',
       title: `DNS NS change: mail.example.com`,
       description: 'Nameserver changed from ns1.original.com to ns1.attacker.com',
       dedupeKey: `dns:mail.example.com:ns:${hashChanges(diff)}`,
       sourceEventId: `mail.example.com:ns:${Date.now()}`,
       metadata: {
         domain: 'mail.example.com',
         recordType: 'NS',
         previous: ['ns1.original.com'],
         current: ['ns1.attacker.com'],
       },
       occurredAt: new Date(),
     });
     // MonitorEventService uses dedupeKey to prevent duplicate events.
     // Event is persisted to MonitorEvent table for audit trail.
     ```
  2. **MonitorAction triggers** — each Monitor can have attached `MonitorAction` rows (configured via `WorldMonitorService.createMonitorAction()`). When a `MonitorEvent` is created, the system fires all active actions for that monitor:
     - **Webhook**: HTTP POST to configured URL with event payload.
     - **Slack**: Post to configured Slack webhook URL.
     - Future: Email, PagerDuty, etc.
  3. **Security findings** → `TrackedFinding.create({ worldId, severity, title, description, valid: true })` — same model used by fuzzing/audit findings. Created for `high`/`critical` severity events.
 **State persistence**: Each `MonitorHandler` updates its `Monitor.recordData` (via `monitorService.update()`) with checkpoint/state after processing events. The `SourceManager` runs continuously — no need for "return updated state" patterns.
 **Slack/webhook policy**:
  - `critical`/`high`: immediate notification via MonitorAction.
  - `medium`: immediate unless suppressed by cooldown.
  - `low`/`info`: grouped digest every 15 minutes.
 **Noise control**:
  - Dedup: `dedupeKey` field on `MonitorEvent` (e.g. `dns:example.com:A:${hashChanges}`). `monitorEventService.createOrGetExisting()` returns existing event if dedupeKey already exists.
  - Cooldown: MonitorAction can be configured with a cooldown window per severity level.
  - Escalations bypass cooldown.

### 8.7 New Object Expansion Scans (bbot-on-discovery)

When a monitor discovers a **new object** (not just an attribute change), we should automatically run a targeted bbot expansion scan for that object.

**Trigger condition**:

 New `DomainNode`, `URLObject`, `IPAddressNode`, or `NetworkServiceNode` created by a `MonitorHandler.handleEvent()` call inside a running monitor.

**Workflow** (triggered from within `MonitorHandler.handleEvent()`, uses the `@asyncTask(HEAVY_OFFCHAIN_QUEUE)` handler from Section 7.2.2):

1. `MonitorHandler.handleEvent()` creates the new entity and persists a `MonitorEvent` via `monitorEventService.createOrGetExisting()`.
2. Handler calls `offchainTasks.executeExpansionScan.applyAsync({ worldId, moduleId, entityType, identityKey })` — sends an SQS message to `HEAVY_OFFCHAIN_QUEUE`.
3. Sentry worker picks up the message and calls `OffchainOrchestrationService.executeExpansionScan()`, which creates a `ModuleRecord` and runs a scoped bbot scan.
4. Worker maps/enriches new findings, updates graph, and creates `TrackedFinding` entries for security-relevant discoveries.

**Expansion scan profile**:

 Use a **targeted, non-exhaustive profile** (fast + safe) instead of full weekly depth.
 Example:
  - New domain: DNS + passive subdomain + lightweight HTTP/TLS checks.
  - New URL: HTTP fingerprinting + technology/security headers.
  - New IP/NetworkService: service fingerprint + TLS cert + basic reputation.

**Infra and guardrails**:

 Expansion tasks use the same `@asyncTask(HEAVY_OFFCHAIN_QUEUE)` handler as weekly scans (shared concurrency cap of 5).
 Deduplicate at the application level before calling `.applyAsync()`: check if a `ModuleRecord` with `(worldId, entityType, identityKey)` was created within the cooldown window (e.g. 6h).
 `HEAVY_OFFCHAIN_QUEUE` uses `ACK_IMMEDIATE` — the worker owns recovery. `ModuleRecord.status` tracks success/failure.

--

## 9. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                        GuardianSentry                           │
│                                                                 │
│  ┌─────────────┐   ┌──────────────────────────────────────────┐ │
│  │ sentry-api  │   │            Offchain Service              │ │
│  │  (REST)     │   │                                          │ │
│  │             │   │  ┌────────────────────────────────────┐  │ │
│  │ PATCH       │   │  │  EventBridge Scheduler             │  │ │
│  │  /worlds/   │   │  │  - Weekly cron → FAST_QUEUE seed   │  │ │
│  │  :id        │◄──│  │                                    │  │ │
│  │             │   │  └────────────────────────────────────┘  │ │
│  │             │   │                                          │ │
│  │ GET /worlds │   │  ┌────────────────────────────────────┐  │ │
│  │  /:id/      │   │  │  Task Queue Workers                │  │ │
│  │  offchain/  │◄──│  │  - HEAVY_OFFCHAIN_QUEUE (bbot)     │  │ │
│  │  status     │   │  │  - MONITOR_QUEUE (real-time)       │  │ │
│  │             │   │  │  - FAST_QUEUE (seeder)             │  │ │
│  │             │   │  │  - @asyncTask pattern               │  │ │
│  │ GET /worlds │   │  └────────────┬───────────────────────┘  │ │
│  │  /:id/      │   │               │                          │ │
│  │  offchain/  │   │    ┌──────────▼──────────┐               │ │
│  │  alerts     │   │    │  Monitoring Plugins  │               │ │
│  │             │   │    │  (MONITOR_MODULES    │               │ │
│  │             │   │    │   registry + runtime │               │ │
│  │             │   │    │   host + handlers)   │               │ │
│  └──────┬──────┘   │    └──────────┬──────────┘               │ │
│         │          │              │                            │ │
│         │          │    ┌─────────▼──────────┐                │ │
│         │          │    │  Sentry Alerts      │                │ │
│         │          │    │  - MonitorEvent     │                │ │
│         │          │    │  - MonitorAction    │                │ │
│         │          │    │  - PG NOTIFY        │                │ │
│         │          │    │  - Socket.IO        │                │ │
│         │          │    │  - TrackedFinding   │                │ │
│         │          │    └────────────────────┘                │ │
│         │          └──────────────────────────────────────────┘ │
│         │                                                       │
│  ┌──────▼─────────────────────────────────────────────────────┐ │
│  │                     PostgreSQL (RDS)                       │ │
│  │                                                            │ │
│  │  WorldGraph ──┬── WorldNode (TPT base)                     │ │
│  │               │    ├── ContractNode (existing)             │ │
│  │               │    ├── DomainNode (new)                    │ │
│  │               │    ├── IPAddressNode (new)                 │ │
│  │               │    ├── IPRangeNode (new)                   │ │
│  │               │    ├── NetworkServiceNode (new)            │ │
│  │               │    ├── CloudResourceNode (new)             │ │
│  │               │    ├── CodeRepositoryNode (new)            │ │
│  │               │    ├── SocialProfileNode (new)             │ │
│  │               │    └── MobileAppNode (new)                 │ │
│  │               │                                            │ │
│  │               └── WorldEdge (STI base)                     │ │
│  │                    ├── ContractEdge (existing)             │ │
│  │                    └── OffchainEdge (new)                  │ │
│  │                                                            │ │
│  │  Model Tables ── URLObject (new, FK → Domain/IP)           │ │
│  │                  EmailAddress (new, FK → Domain)            │ │
│  │                                                            │ │
│  │  Existing ── TrackedFinding (vuln + secret findings)       │ │
│  │             ModuleRecord (monitor state in recordData)     │ │
│  │             MonitorEvent (alert events)                    │ │
│  │                                                            │ │
│  │  OffchainScanSnapshot (new)                                │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │                        S3                                  │ │
│  │  Raw bbot JSONL output + scan artifacts (2 week retention) │ │
│  └────────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

--

## 10. Database Schema Changes

### 10.1 New Node Tables (8 Tables)

Each entity type from Section 4.4 becomes a new table extending `WorldNode` via TPT. The ORM auto-joins with the `WorldNode` base table on the shared primary key `id` (UUID v7).

Table naming convention: `{EntityType}Node` (e.g. `DomainNode`, `IPAddressNode`).

| Table | Identity Key | Unique Constraint |
|-------|-------------|-------------------|
| `DomainNode` | `name` | `(worldGraphId, name)` |
| `IPAddressNode` | `address` | `(worldGraphId, address)` |
| `IPRangeNode` | `cidr` | `(worldGraphId, cidr)` |
| `NetworkServiceNode` | `endpoint` | `(worldGraphId, endpoint)` |
| `CloudResourceNode` | `resource_id` | `(worldGraphId, resource_id)` |
| `CodeRepositoryNode` | `repo_url` | `(worldGraphId, repo_url)` |
| `SocialProfileNode` | `platform_handle` | `(worldGraphId, platform_handle)` |
| `MobileAppNode` | `store_id` | `(worldGraphId, store_id)` |

### 10.2 New Model Tables (2 Tables)

```sql
CREATE TABLE "URLObject" (
  "id" UUID PRIMARY KEY,  -- UUID v7
  "worldId" UUID NOT NULL REFERENCES "World"("id") ON DELETE CASCADE,
  "domainId" UUID REFERENCES "DomainNode"("id") ON DELETE SET NULL,
  "ipAddressId" UUID REFERENCES "IPAddressNode"("id") ON DELETE SET NULL,
  "url" TEXT NOT NULL,
  -- ... all URLObject columns from Section 4.5.1
  UNIQUE ("worldId", "url")
);
CREATE INDEX idx_url_object_domain ON "URLObject" ("domainId");
CREATE INDEX idx_url_object_ip ON "URLObject" ("ipAddressId");

CREATE TABLE "EmailAddress" (
  "id" UUID PRIMARY KEY,  -- UUID v7
  "worldId" UUID NOT NULL REFERENCES "World"("id") ON DELETE CASCADE,
  "domainId" UUID REFERENCES "DomainNode"("id") ON DELETE SET NULL,
  "address" VARCHAR(320) NOT NULL,
  -- ... all EmailAddress columns from Section 4.5.2
  UNIQUE ("worldId", "address")
);
CREATE INDEX idx_email_domain ON "EmailAddress" ("domainId");
```

### 10.3 New Edge Subtype

```sql
- OffchainEdge uses STI (no new table — discriminator column in WorldEdge)
- Just needs the 'offchain' discriminator value
ALTER TABLE "WorldEdge"
  ADD CONSTRAINT chk_edge_type CHECK ("edgeType" IN ('base', 'contract', 'offchain'));
```

### 10.4 Monitor State — ModuleRecord.recordData

Monitor state is tracked via the existing `ModuleRecord.recordData` JSON field. Each monitoring plugin stores its last-known state, last check time, and checkpoint data in the module record that Sentry creates for the queued monitoring task.

```typescript
// Example recordData for DNS monitor source (ModuleRecord for the source)
{
  monitorType: 'offchain-dns-monitor',
  sourceType: 'OffchainDns',
  sourceKey: 'offchain-dns:<worldId>',
  worldId: '<worldId>',
}

// Example recordData for individual Monitor row
{
  worldId: '<worldId>',
  domainStates: {
    'mail.example.com': {
      dns_a: ['93.184.216.34'],
      dns_mx: [{ priority: 10, host: 'mx.example.com' }],
    }
  },
  lastCheckedAt: '2026-04-13T00:00:30Z',
  checkCount: 42,
}
```

> **No dedicated `OffchainMonitorState` table needed** — this reuses Sentry's existing module record infrastructure.

### 10.5 Alert Events — MonitorEvent

Offchain alerts use Sentry's `MonitorEvent` table for recording alert events. Security findings (vulnerabilities, secrets) additionally create `TrackedFinding` records.

> **No dedicated `OffchainAlert` table needed** — this reuses Sentry's existing monitoring event infrastructure.

### 10.6 Scan Snapshot Table

```sql
CREATE TABLE "OffchainScanSnapshot" (
  "id" UUID PRIMARY KEY,
  "worldId" UUID NOT NULL REFERENCES "World"("id") ON DELETE CASCADE,
  "scanType" VARCHAR(20) NOT NULL,     -- 'weekly', 'expansion'
  "startedAt" TIMESTAMPTZ NOT NULL,
  "completedAt" TIMESTAMPTZ,
  "status" VARCHAR(20) NOT NULL,       -- 'running', 'completed', 'failed'
  "nodesCreated" INTEGER DEFAULT 0,
  "nodesUpdated" INTEGER DEFAULT 0,
  "edgesCreated" INTEGER DEFAULT 0,
  "alertsGenerated" INTEGER DEFAULT 0,
  "error" TEXT,
  "metadata" JSONB                     -- Module-specific stats
);
CREATE INDEX idx_snapshot_world ON "OffchainScanSnapshot" ("worldId", "startedAt" DESC);
```

### 10.7 Queuing — Existing Sentry Task Queue & Monitoring Plugin System

Weekly scans and expansion scans use SQS via Sentry's `@asyncTask` pattern. Real-time monitors use the monitoring plugin system's dedicated `MONITOR_QUEUE`. No dedicated database queue tables are needed:

 **Weekly scans**: `HEAVY_OFFCHAIN_QUEUE` SQS queue (Section 7.2).
 **Expansion scans**: same `HEAVY_OFFCHAIN_QUEUE` (Section 8.7).
 **Real-time monitors**: `MONITOR_QUEUE` SQS queue (Section 8.2.1) — the existing dedicated monitoring queue from branch `202604_UpdateMonitors`. Long-lived `SourceManager` processes run on workers polling this queue, with `pg_advisory_lock` preventing duplicates and Postgres NOTIFY enabling hot reconfiguration.

SQS handles ordering, retry, and dead-letter queue semantics natively.

> **No `OffchainWeeklyScanQueue` or `OffchainExpansionQueue` tables needed** — SQS replaces the DB-level queue.

### 10.8 World Model Extension

All offchain configuration fields are added as **top-level columns** on the `World` entity (see Section 3.3). This avoids JSON-blob queries and provides full ORM type safety.

--

## 11. Module System Integration

### 11.1 New Module Types

**Weekly scans** extend the existing `BuildingModuleType` enum:

```typescript
export enum BuildingModuleType {
  // Existing
  ContractGraph = 'contract-graph',
  BbotDiscovery = 'bbot-discovery',

  // New
  OffchainWeeklyScan = 'offchainWeeklyScan',
}

// Registration in building modules registry
export const BUILDING_MODULES: Record<BuildingModuleType, WorldBuildingModule<any>> = {
  [BuildingModuleType.ContractGraph]: new ContractGraphModule(),
  [BuildingModuleType.BbotDiscovery]: new BbotDiscoveryModule(),
  [BuildingModuleType.OffchainWeeklyScan]: new OffchainWeeklyScanModule(),
};
```

**Real-time monitors** extend the existing `MonitorModuleType` in Sentry's monitoring plugin registry (`src/monitoring/modules/registry.ts`). Each specific monitor (DNS, CT, WHOIS, etc.) is a **monitoring plugin** registered in `MONITOR_MODULES` — the same registry used by the existing `contract-event-monitor` and `safe-monitor`:

```typescript
// src/monitoring/modules/registry.ts — extend existing MONITOR_MODULE_TYPES
export const MONITOR_MODULE_TYPES = [
  'contract-event-monitor',   // existing
  'safe-monitor',             // existing
  // New offchain monitors
  'offchain-dns-monitor',
  'offchain-ct-monitor',
  'offchain-whois-monitor',
  'offchain-cert-expiry-monitor',
  'offchain-subdomain-monitor',
  'offchain-reputation-monitor',
  'offchain-leak-monitor',
  'offchain-github-monitor',
  'offchain-phishing-monitor',
  'offchain-discord-monitor',
  'offchain-x-monitor',
] as const;

// Each type registered in MONITOR_MODULES with MonitorModuleDefinition
// (see Section 8.2.2 for full registration example)
```

### 11.2 Module Record Data

**Weekly scan** — `ModuleRecord.recordData` for `OffchainWeeklyScan`:

```typescript
export interface OffchainWeeklyScanRecordData {
  domains: string[];
  snapshotId: string;
  // Module-specific state
}
```

**Real-time monitors** — two levels of state (same as existing `contract-event-monitor`):

```typescript
// ModuleRecord.recordData (per-source, managed by WorldMonitorService)
export interface OffchainMonitorSourceRecordData {
  monitorType: string;  // 'offchain-dns-monitor', 'offchain-ct-monitor', etc.
  sourceType: string;   // e.g. 'OffchainDns'
  sourceKey: string;    // e.g. 'offchain-dns:<worldId>'
  worldId: string;
}

// Monitor.recordData (per-monitor rule, managed by MonitorHandler)
// Contains per-entity state for change detection
export interface OffchainDnsMonitorRecordData {
  worldId: string;
  domainStates: Record<string, DnsState>;
  lastCheckedAt: string;
  checkCount: number;
}
```

### 11.3 Module Lifecycle

```
World Created
    │
    ├── Admin configures offchain fields on World
    │
    ├── POST /worlds/:id/offchain/start
    │     │
    │     ├── Sets offchainStatus = 'active'
    │     │
    │     ├── Creates OffchainWeeklyScan ModuleRecord (phase: build)
    │     │     └── EventBridge schedule registered for weekly kickoff
    │     │
    │     └── Creates Monitor rows via WorldMonitorService
    │           └── WorldMonitorService.createAndStartMonitor(worldId, type, data)
    │                 ├── Creates ModuleRecord (phase: Monitor, status: Running)
    │                 ├── Creates Monitor row (per-monitor config in recordData)
    │                 └── Dispatches to MONITOR_QUEUE via .applyAsync()
    │
    ├── Weekly cron fires (EventBridge → FAST_QUEUE seeder)
    │     └── Seeder enqueues HEAVY_OFFCHAIN_QUEUE task for this World
    │           └── Worker runs bbot end-to-end
    │
    └── MONITOR_QUEUE worker picks up monitor task
          └── MonitorRuntimeHost.startMonitor(moduleId)
                ├── Acquires pg_advisory_lock (prevents duplicates)
                ├── Creates SourceManager (long-lived polling loop)
                ├── Creates MonitorHandler per Monitor row
                ├── Starts 10s heartbeat → ModuleRecord.heartbeatAt
                ├── Subscribes to Postgres NOTIFY for control events
                └── Deltas detected → MonitorEvent + MonitorAction triggers
```

--

## 12. API Surface

### 12.1 New Endpoints

**Offchain configuration & scan endpoints**:

| Method | Path | Description |
|--------|------|-------------|
| `PATCH` | `/worlds/:id` | Update world (including offchain top-level fields) |
| `POST` | `/worlds/:id/offchain/start` | Start offchain monitoring (creates weekly schedule + monitors) |
| `POST` | `/worlds/:id/offchain/stop` | Stop offchain monitoring (pauses all monitors + cancels schedule) |
| `GET` | `/worlds/:id/offchain/status` | Get monitoring status (monitors, last scan, next scan) |
| `GET` | `/worlds/:id/offchain/scans` | Get scan history |
| `POST` | `/worlds/:id/offchain/scan/trigger` | Manually trigger weekly scan |
| `GET` | `/worlds/:id/offchain/entities/:type` | Get entities by type (paginated) |
| `GET` | `/worlds/:id/offchain/diff/:snapshotId1/:snapshotId2` | Diff two scan snapshots |

**Monitor CRUD** — uses the existing `WorldMonitorService` API (same routes used by `contract-event-monitor` and `safe-monitor`):

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/worlds/:id/monitors` | List all monitors (via `WorldMonitorService.listMonitors`) |
| `POST` | `/worlds/:id/monitors` | Create monitor (via `WorldMonitorService.createAndStartMonitor`) |
| `GET` | `/worlds/:id/monitors/:monitorId` | Get monitor details |
| `PATCH` | `/worlds/:id/monitors/:monitorId` | Update monitor config (via `WorldMonitorService.updateMonitor`) |
| `POST` | `/worlds/:id/monitors/:monitorId/pause` | Pause monitor |
| `POST` | `/worlds/:id/monitors/:monitorId/resume` | Resume monitor |
| `DELETE` | `/worlds/:id/monitors/:monitorId` | Delete monitor |

**Monitor events & actions** — uses the existing `WorldMonitorService` event/action API:

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/worlds/:id/monitors/events` | List monitor events (paginated, filterable) |
| `GET` | `/worlds/:id/monitors/events/:eventId` | Get event details |
| `PATCH` | `/worlds/:id/monitors/events/:eventId` | Update event status (acknowledge/dismiss) |
| `GET` | `/worlds/:id/monitors/:monitorId/actions` | List actions for a monitor |
| `POST` | `/worlds/:id/monitors/:monitorId/actions` | Create action (webhook/Slack trigger) |
| `PATCH` | `/worlds/:id/monitors/actions/:actionId` | Update action config |
| `DELETE` | `/worlds/:id/monitors/actions/:actionId` | Delete action |

### 12.2 Socket.IO Events

Socket.IO events are used for real-time UI updates during weekly scans. Real-time monitor alerts are primarily persisted via `MonitorEvent` + `MonitorAction` triggers (see Section 8.6), but Socket.IO events can supplement for live dashboard updates.

| Event | Direction | Payload | Description |
|-------|-----------|---------|-------------|
| `offchain:alert` | Server → Client | `{worldId, alert}` | New alert generated (from weekly scan diffs) |
| `offchain:entityDiscovered` | Server → Client | `{worldId, entityType, entity}` | New entity found (real-time) |
| `offchain:entityUpdated` | Server → Client | `{worldId, entityType, entityId, changes}` | Entity attributes changed |
| `offchain:scanProgress` | Server → Client | `{worldId, scanId, progress, nodesFound}` | Weekly scan progress (via `emitProgress()`) |
| `offchain:monitorStatus` | Server → Client | `{worldId, monitors[]}` | Monitor health status |

--

## 13. Alerting & Diffing

### 13.1 Alert Severity Classification

| Severity | Triggers |
|----------|----------|
| **Critical** | New vulnerability (CVSS ≥ 9.0), credential leak with plaintext password, domain about to expire (< 1 day), subdomain takeover detected |
| **High** | New vulnerability (CVSS 7.0–8.9), DNS NS/A record changed, TLS cert expired or self-signed, new secret exposed in public repo, IP blacklisted |
| **Medium** | New subdomain discovered, DNS record changed (MX, TXT), cert expiring < 14 days, new cloud resource found public, WHOIS registrar changed |
| **Low** | New email discovered, new social profile found, technology version changed, cert expiring < 30 days, new code repo discovered |
| **Info** | New IP geolocation data, CDN/provider classification changed, repository metadata updated |

### 13.2 Change Diffing

Each entity type implements a `diff()` method comparing current vs previous state:

```typescript
interface EntityDiff {
  entityType: WorldNodeType;
  entityId: string;
  identityKey: string; // e.g. FQDN, IP, URL
  changes: AttributeChange[];
  isNew: boolean;
  isRemoved: boolean;
}

interface AttributeChange {
  attribute: string;
  previousValue: any;
  currentValue: any;
  severity: AlertSeverity;
}
```

### 13.3 Weekly Scan Diffing

After each weekly scan completes:

1. Load previous scan's entity set from `OffchainScanSnapshot`
2. Compare against current scan's entity set
3. Classify changes:
   - **New entities** — not present in previous scan
   - **Removed entities** — present in previous but not current (may indicate takedown, decommission)
   - **Modified entities** — attribute values changed
4. Generate alerts for all changes above info severity (as `MonitorEvent` records + Socket.IO)
5. Generate `TrackedFinding` records for security-relevant discoveries
6. Store snapshot reference for next diff

--

## 14. Migration from Current NetworkNode

The current `NetworkNode` model stores all bbot events as a single flat entity with generic fields. This RFC replaces it with richly-typed entity nodes and model tables.

### 14.1 Migration Strategy

1. **Phase 1 — Schema creation**: Add 8 new node tables + 2 model tables + OffchainEdge discriminator. Keep `NetworkNode` intact.
2. **Phase 2 — Dual-write**: New `OffchainWeeklyScanModule` writes to new entity tables. Old `BbotDiscoveryModule` continues writing to `NetworkNode` for backward compatibility.
3. **Phase 3 — Data migration**: Script to migrate existing `NetworkNode` rows into typed entity tables:

| NetworkNode.eventType | Migration Target |
|----------------------|------------------|
| `DNS_NAME` | DomainNode |
| `IP_ADDRESS` | IPAddressNode |
| `OPEN_TCP_PORT` | NetworkServiceNode |
| `URL` / `HTTP_RESPONSE` | URLObject |
| `TECHNOLOGY` | URLObject.technologies attribute |
| `VULNERABILITY` / `FINDING` | TrackedFinding |
| `EMAIL_ADDRESS` | EmailAddress |
| `STORAGE_BUCKET` | CloudResourceNode |
| `WAF` | URLObject.waf attribute |

4. **Phase 4 — Deprecate NetworkNode**: Remove `NetworkNode` table and old `BbotDiscoveryModule`. Update UI and API to use new entity types.

### 14.2 WorldNodeType Backward Compatibility

The implemented `WorldNodeType` enum currently contains `contract` plus the new offchain types from Section 4.3. Deprecated aliases for old `NetworkNode`-style values are **not** implemented in this codebase; backward compatibility during migration is handled at the data-migration/application layer rather than via enum aliases.

--

## 15. Open Questions

| # | Question | Options | Decision |
|---|----------|---------|----------|
| 1 | How to handle rate limiting across multiple Worlds using the same API keys? | (a) Per-world rate limits (b) Global rate pool (c) Per-API-key rate pool | TBD |
| 2 | Should we store full HTTP response bodies in URLObject? | (a) Always (b) Only for root URLs (c) Never (hash only) (d) Configurable | TBD |
| 3 | Should the old `BbotDiscoveryModule` continue running during the weekly scan or be fully replaced? | (a) Replace entirely (b) Keep as "quick scan" option | TBD |
| 4 | How long to retain `OffchainScanSnapshot` history? | (a) 90 days (b) 1 year (c) Configurable | TBD |
| 5 | How to handle bbot modules that require external tools (massdns, nuclei, naabu)? | (a) Pre-install in Docker image (b) Lazy download on first use (c) Optional modules disabled if tool missing | TBD |

--

## Appendix A: Entity → bbot Event Mapping

Complete mapping of bbot events to the new entity model:

| bbot Event | New Entity | Key Transformation |
|-----------|-----------|-------------------|
| `DNS_NAME` | DomainNode | FQDN → `name`, but only when the name stays inside the seeded domain roots |
| `DNS_NAME_UNRESOLVED` | DomainNode (`is_resolved: false`) | Same entity, state flag, same seeded-domain restriction |
| `RAW_DNS_RECORD` | DomainNode DNS attributes | Parsed into typed fields (`dns_a`, `dns_mx`, etc.); non-scope answers do not widen scope |
| `IP_ADDRESS` | IPAddressNode | IP string → `address`, but only for explicit IP seeds or `A` / `AAAA` results of in-scope domains |
| `IP_RANGE` | IPRangeNode | CIDR → `cidr` |
| `URL` | URLObject (`is_verified: true`) | Full URL → `url`, FK links to DomainNode/IPAddressNode only when the host stays inside enforced domain/IP scope |
| `URL_UNVERIFIED` | URLObject (`is_verified: false`) | Same entity, verification state |
| `URL_HINT` | URLObject (`is_verified: false`) | Low-confidence discovery currently maps to the same persisted fields as other unverified URLs |
| `HTTP_RESPONSE` | URLObject attributes | Status, headers, body → URLObject attrs |
| `WAF` | URLObject.`waf` | WAF info becomes URLObject attribute |
| `TECHNOLOGY` | URLObject.`technologies[]` | Tech info becomes URLObject attribute |
| `VHOST` | URLObject.`host` / `responseHeaders` / related DomainNode context | No dedicated `vhosts[]` field is implemented |
| `WEBSCREENSHOT` | deferred / raw artifact only | No `screenshot_b64` attribute is implemented on `URLObject` |
| `GEOLOCATION` | IPAddressNode geo attributes | Geo data attached only to an already-allowed IP |
| `OPEN_TCP_PORT` | NetworkServiceNode (`transport: tcp`) | `host:port` → NetworkServiceNode |
| `OPEN_UDP_PORT` | NetworkServiceNode (`transport: udp`) | Same pattern |
| `PROTOCOL` | NetworkServiceNode.`protocol` | Protocol is service attribute |
| `EMAIL_ADDRESS` | EmailAddress | Email string → `address`, FK links to DomainNode |
| `SOCIAL` | SocialProfileNode | Platform + handle → `platform_handle` |
| `PASSWORD` | TrackedFinding (`severity: high`) | Exposed password → finding with location/poc |
| `HASHED_PASSWORD` | TrackedFinding (`severity: high`) | Hash + algorithm → finding |
| `VULNERABILITY` | TrackedFinding | Dict → severity/title/description/poc/location |
| `FINDING` | TrackedFinding or entity attribute | Mapped by finding type |
| `STORAGE_BUCKET` | CloudResourceNode (`resource_type: storage_bucket`) | Bucket → cloud resource |
| `AZURE_TENANT` | CloudResourceNode (`resource_type: tenant`) | Tenant → cloud resource |
| `CODE_REPOSITORY` | CodeRepositoryNode | Repo URL → `repo_url`, but only for exact seeded repos or repos under seeded owners/orgs |
| `MOBILE_APP` | MobileAppNode | Store + ID → `store_id` |
| `ASN` | IPAddressNode/IPRangeNode attributes (`asn`, `isp`, `range_name`, `country`) | ASN data attached to IP/IP range, no standalone ASN node |
| `FILESYSTEM` | TrackedFinding metadata (`location`) | File evidence retained as finding provenance |
| `USERNAME` | SocialProfileNode.`platform_handle` or CodeRepositoryNode.`owner` | Username captured as field on related entities |

--

## Appendix B: Relationship Graph Visualization

```
Domain ──resolves_to──▶ IPAddress
Domain (sub) ──is_subdomain_of──▶ Domain (parent)
Domain ──cname_to──▶ Domain

IPAddress ──in_range──▶ IPRange
IPAddress ──runs_service──▶ NetworkService

IPRange ──subnet_of──▶ IPRange (parent)

NetworkService ──runs_on──▶ IPAddress

CloudResource ──associated_domain──▶ Domain

-- Foreign Key relationships (non-edge) ---
URLObject.domain_id ──FK──▶ DomainNode
URLObject.ip_address_id ──FK──▶ IPAddressNode
EmailAddress.domain_id ──FK──▶ DomainNode
SocialProfileNode.email_id ──FK──▶ EmailAddress
DomainNode.parent_domain_id ──FK──▶ DomainNode
```

--

## Appendix C: bbot CLI Configuration

### Weekly Full Scan Command

```bash
bbot \
  -t "guardianaudits.com,guardian.xyz" \
  -n "world-${WORLD_ID}" \
  --json \
  -y \
  -p all-but-intense-http \
  -c \
    modules.shodan_dns.api_key=${SHODAN_API_KEY} \
    modules.virustotal.api_key=${VIRUSTOTAL_API_KEY} \
    modules.github_org.api_key=${GITHUB_TOKEN} \
    modules.censys.api_id=${CENSYS_API_ID} \
    modules.censys.api_secret=${CENSYS_API_SECRET}
```

### Template Selection Policy

Use bbot's maintained `all-but-intense-http` template directly instead of maintaining a custom static preset in this RFC.

--

## Appendix D: Docker Deployment

Offchain monitoring runs within the **existing Sentry worker infrastructure** — the same workers that poll `FAST_QUEUE`, `SLOW_QUEUE`, and `MONITOR_QUEUE`. The only addition is installing bbot (Python) into the worker image so that `HEAVY_OFFCHAIN_QUEUE` tasks can spawn bbot scans.

```dockerfile
# Dockerfile.sentry-worker (extend existing worker image)
FROM python:3.11-slim AS bbot-base

# Install bbot and external tools
RUN pip install bbot
RUN bbot --install-all-deps  # Downloads massdns, nuclei, naabu, etc.

FROM node:20-slim AS sentry-worker

# Copy bbot from Python stage
COPY --from=bbot-base /usr/local /usr/local
COPY --from=bbot-base /root/.bbot /root/.bbot

WORKDIR /app
COPY package.json pnpm-lock.yaml ./
RUN corepack enable && pnpm install --frozen-lockfile

COPY src/ src/
RUN pnpm build

# Same entry point as existing Sentry worker — polls ALL_QUEUES
# including HEAVY_OFFCHAIN_QUEUE and MONITOR_QUEUE
CMD ["node", "dist/task-queue/worker/index.js"]
```

**Deployment notes**:
 Workers polling `HEAVY_OFFCHAIN_QUEUE` need bbot installed (use the extended image above).
 Workers polling `MONITOR_QUEUE` do NOT need bbot — they run lightweight polling loops (DNS, HTTP, API calls).
 You can run separate worker pools per queue (e.g. `MONITOR_QUEUE_CONCURRENCY=10` for monitoring, `HEAVY_OFFCHAIN_QUEUE` workers with bbot). The existing `ALL_QUEUES` configuration in `queues.ts` controls which queues each worker polls.
 Environment variables (API keys, `DATABASE_URL`, SQS endpoints) are injected at deployment via the same mechanism used by existing Sentry workers.
