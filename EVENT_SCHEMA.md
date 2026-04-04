# Event Object Schema — Redesigned Model


## Design Principles

1. **Entities are real-world objects** — a domain, an IP, a URL. If it exists independently in the attack surface, it's an entity.
2. **Attributes are properties of entities** — a WAF protecting a URL, DNS records of a domain, geolocation of an IP. If it only makes sense in the context of its parent, it's an attribute.
3. **Relationships are first-class** — "Domain resolves to IP" is an explicit, typed, directional link — not an implicit parent/child chain.
4. **No "Finding" dumping ground** — every piece of data should have a structured home in a specific entity or as an attribute of one. There is no generic catch-all.
5. **Deduplication by identity** — each entity has a natural key (domain name, IP string, URL). Attributes enrich rather than duplicate.
6. **Entities are only valid objects belonging to the scanned organization** - We are only interested in generating entities that BELONG to the scanned organizations. E.g. If we scan *.guardianaudits.com, then www.guardianaudits.com is a valid new domain (subdomains) entity, but "aspmx2.googlemail.com", the MX server of guardianaudits.com doesn't belong to GuardianAudits (and to the scope of *.guardianaudits.com), so we shouldn't generate a domain entity for "aspmx2.googlemail.com".

---

## bbot events that shouldn't be entities

| bbot concept | New model | Rationale |
|---|---|---|
| `WAF` event | Attribute of **URL** | A WAF is a property of a web endpoint, not a standalone object |
| `TECHNOLOGY` event | Attribute of **URL** or **Service** | "runs Apache" is a property of the thing running it |
| `PROTOCOL` event | Attribute of **Service** | SSH, FTP, HTTP are properties of a service on a port |
| `VHOST` event | Attribute of **URL** / **IP** | Virtual hosts are config of a server |
| `HTTP_RESPONSE` event | Attributes of **URL** | Status code, headers, body are properties of a visited URL |
| `WEBSCREENSHOT` event | Attribute of **URL** | A screenshot is a property of the page |
| `GEOLOCATION` event | Attribute of **IP Address** | Location is a property of an IP |
| `RAW_DNS_RECORD` event | Attribute of **Domain** | DNS records are properties of a domain |
| `DNS_NAME_UNRESOLVED` event | **Domain** with `is_resolved: false` | Same entity, different state |
| `URL_UNVERIFIED` event | **URL** with `is_verified: false` | Same entity, different state |
| `URL_HINT` event | **URL** with `is_verified: false, confidence: low` | Same entity, low certainty |
| `OPEN_TCP_PORT` event | **Service** entity | Port + service info combined into one rich entity |
| `FINDING` event | Removed — data goes into **Vulnerability** or entity attributes | No generic catch-all; use structured entities |
| `PASSWORD` / `HASHED_PASSWORD` | **Secret** entity | Credentials get their own rich entity |
| `SOCIAL` event | **Social Profile** entity | Rich attributes per platform |
| `ASN` event (dict blob) | Attribute of **IPRANGE** / **IP** | ASN are properties of related IP addresses |
| `AZURE_TENANT` event | **Cloud Resource** entity | Generalized to cover AWS/GCP/Azure |

---

## Entity Catalog

### Overview

| # | Entity | Identity Key | Category | Source in bbot | Source in hackermate |
|---|--------|-------------|----------|----------------|---------------------|
| 1 | **Domain** | FQDN | Core Asset | `DNS_NAME` | `Domain` node |
| 2 | **IP Address** | IP string | Core Asset | `IP_ADDRESS` | `Ip` node |
| 3 | **IP Range** | CIDR notation | Core Asset | `IP_RANGE` | `Range` node |
| 4 | **URL** | Full URL | Core Asset | `URL`/`URL_UNVERIFIED`/`HTTP_RESPONSE` | `Web` node |
| 5 | **Email Address** | email string | Core Asset | `EMAIL_ADDRESS` | `Email` node |
| 6 | **Service** | ip:port/transport | Infrastructure | `OPEN_TCP_PORT`/`PROTOCOL` | `Service` node + `RUNNING_SERVICE` rel |
| 7 | **ASN** | AS number | Infrastructure | `ASN` | `ASN` node |
| 8 | **Cloud Resource** | provider:type:id | Infrastructure | `AZURE_TENANT`/`STORAGE_BUCKET` | — |
| 9 | **Code Repository** | URL | Asset | `CODE_REPOSITORY` | — |
| 10 | **Username** | string | Identity | `USERNAME` | `Username` node |
| 11 | **Social Profile** | platform:handle | Identity | `SOCIAL` | `Twitter`/`LinkedIn`/`GitHub`/`Facebook` nodes |
| 12 | **Mobile App** | store:id | Asset | `MOBILE_APP` | — |
| 13 | **Vulnerability** | dedupe_key | Intelligence | `VULNERABILITY` | `Vulnerability` node |
| 14 | **Secret** | hash of value | Intelligence | `PASSWORD`/`HASHED_PASSWORD`/findings | `LeakedSecret` model |
| 15 | **Leak** | name+date | Intelligence | — | `Leak` node |
| 16 | **Paste** | url | Intelligence | — | `Paste` node |
| 17 | **File** | path or hash | Asset | `FILESYSTEM` | — |


**IMPORTANT TO KNOW**: The defined attributes are suggestions and might slightly change during implementation .

---

## 1. Domain

> A DNS domain or subdomain. The central object for attack surface mapping.

### Identity
- **name** `string` — FQDN (e.g. `mail.example.com`)

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `is_subdomain` | `bool` | Whether this is a subdomain (vs registered domain) |
| `is_resolved` | `bool` | Whether DNS resolution succeeded in A, AAAA or CNAME |
| `is_wildcard` | `bool` | Whether the domain has wildcard DNS |
| `wildcard_ips` | `string[]` | IPs returned by wildcard resolution |
| **DNS Records** | | |
| `dns_a` | `string[]` | A records (IPv4 addresses) |
| `dns_aaaa` | `string[]` | AAAA records (IPv6 addresses) |
| `dns_cname` | `string[]` | CNAME records |
| `dns_mx` | `{priority: int, host: string}[]` | MX records |
| `dns_ns` | `string[]` | Nameserver records |
| `dns_txt` | `string[]` | TXT records (raw) |
| `dns_soa` | `{mname: string, rname: string, serial: int, ...}` | SOA record |
| `dns_srv` | `{priority: int, weight: int, port: int, target: string}[]` | SRV records |
| `dns_caa` | `{flags: int, tag: string, value: string}[]` | CAA records |
| `dns_ptr` | `string[]` | PTR records |
| **Email Security** | | |
| `spf` | `string` | SPF record (raw TXT) |
| `dmarc` | `string` | DMARC record (raw TXT) |
| `dkim_selectors` | `{selector: string, record: string}[]` | DKIM selectors found |
| `bimi` | `string` | BIMI record |
| `tls_rpt` | `string` | MTA-STS / TLS-RPT record |
| **TLS Certificate** | | |
| `certificate` | `{subject_cn: string, issuer_cn: string, issuer_org: string, serial_number: string, not_before: datetime, not_after: datetime, san_domains: string[], san_ips: string[], key_algorithm: string, key_size: int, signature_algorithm: string, is_self_signed: bool, is_expired: bool, is_wildcard: bool, fingerprint_sha256: string, transparency_logs: bool}` | TLS certificate covering this domain |
| **WHOIS** | | |
| `registrar` | `string` | Domain registrar |
| `registration_date` | `datetime` | When the domain was registered |
| `expiration_date` | `datetime` | Registration expiry date |
| `updated_date` | `datetime` | Last WHOIS update |
| `registrant_name` | `string` | Registrant name |
| `registrant_email` | `string` | Registrant email |
| `registrant_org` | `string` | Registrant organisation |
| `registrant_country` | `string` | Registrant country |
| `dnssec` | `bool` | Whether DNSSEC is enabled |
| `status` | `string[]` | Domain status codes (e.g. `clientTransferProhibited`) |
| **Recon Metadata** | | |
| `zone_transfer_possible` | `bool` | Whether AXFR is allowed |
| `phishing_like_domains_history` | `{phishing_domain: string, first_seen: datetime, last_seen: datetime}[]` | Whether AXFR is allowed |
| `ip_history` | `{ip: string, first_seen: datetime, last_seen: datetime}[]` | Historical IP resolutions |
| **Cloud Metadata** | | |
| `is_google_worskpace` | `bool` | Whether the domain is used in google workspace |
| `is_entraid_worskpace` | `bool` | Whether the domain is used in Entra ID |


### Relationships

| Relationship | Target | Description |
|---|---|---|
| `resolves_to` | **IP Address** | A/AAAA resolution (with record type) |
| `has_subdomain` | **Domain** | Parent → child subdomain |
| `cname_to` | **Domain** | CNAME alias (ONLY IF THE CNAME DOMAIN IS PART OF THE SCOPE) |
| `has_email` | **Email Address** | Emails associated with this domain |
| `hosts` | **URL** | Web endpoints hosted on this Domain |

---

## 2. IP Address

> An IPv4 or IPv6 address.

### Identity
- **address** `string` — IP address (e.g. `93.184.216.34`)

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `version` | `enum: v4, v6` | IP version |
| `is_private` | `bool` | RFC1918 / private address |
| `reverse_dns` | `string[]` | PTR records |
| **Geolocation** | | |
| `country` | `string` | Country code |
| `country_name` | `string` | Full country name |
| `region` | `string` | State / region |
| `city` | `string` | City |
| `latitude` | `float` | Latitude |
| `longitude` | `float` | Longitude |
| `timezone` | `string` | Timezone |
| **Network** | | |
| `asn` | `int` | AS number |
| `isp` | `string` | Internet service provider |
| `org` | `string` | Organisation name |
| **Classification** | | |
| `is_cdn` | `bool` | CDN address |
| `cdn_name` | `string` | CDN provider (Cloudflare, Akamai, ...) |
| `cloud_provider` | `string` | Cloud provider (AWS, GCP, Azure, ...) |
| `provider_type` | `enum: hosting, residential, business, education, government` | Type of provider |
| `is_vpn` | `bool` | Known VPN endpoint |
| `is_proxy` | `bool` | Known proxy |
| `is_tor` | `bool` | Tor exit node |
| **Reputation** | | |
| `risk_score` | `int` | Reputation risk score (0-100) |
| `os` | `string` | Detected operating system |
| `blacklisted` | `bool` | Currently on any blacklist |
| `blacklist_sources` | `{source: string, type: string, listed_date: datetime}[]` | Blacklist entries |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `in_range` | **IP Range** | Belongs to IP range |
| `runs` | **Service** | Services running on this IP |
| `hosts` | **URL** | Web endpoints hosted on this IP |

---

## 3. IP Range

> A CIDR block / network range.

### Identity
- **cidr** `string` — CIDR notation (e.g. `93.184.216.0/24`)

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `version` | `enum: v4, v6` | IP version |
| `size` | `int` | Number of addresses |
| `name` | `string` | Range name/description (from RIR) |
| `country` | `string` | Country code |
| `asn` | `int` | AS number |


### Relationships

| Relationship | Target | Description |
|---|---|---|
| `contains` | **IP Address** | IPs in this range |
| `subnet_of` | **IP Range** | Parent range |
| `has_subnet` | **IP Range** | Child ranges |

---

## 4. URL

> An HTTP(S) endpoint. Consolidates bbot's URL, URL_UNVERIFIED, HTTP_RESPONSE, and absorbs WAF/Technology/CMS/Screenshot as attributes.

### Identity
- **url** `string` — Full root URL (e.g. `https://example.com/`)

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| **URL Components** | | |
| `scheme` | `string` | http / https |
| `host` | `string` | Hostname or IP |
| `port` | `int` | Port number |
| **HTTP Response** (populated after visit) | | |
| `status_code` | `int` | HTTP status code |
| `title` | `string` | HTML page title |
| `content_type` | `string` | Response Content-Type |
| `content_length` | `int` | Response body size |
| `response_headers` | `{name: string, value: string}[]` | All response headers |
| `response_body_hash` | `string` | Hash of response body |
| `response_body` | `string` | Full/partial response body (optional, large) |
| **Technologies** | | |
| `technologies` | `{name: string, version?: string, category?: string, confidence?: int}[]` | Detected technologies (frameworks, libraries, servers) |
| `cms` | `{name: string, version?: string, plugins?: string[], themes?: string[]}` | Detected CMS |
| `server` | `string` | Server header value |
| **Security** | | |
| `waf` | `{name: string, info?: string}` | Detected WAF/protection |
| `security_headers` | `{header: string, present: bool, value?: string, rating: string}[]` | Security header audit |
| `csp` | `string` | Content-Security-Policy |
| `cors_origin` | `string` | Access-Control-Allow-Origin |
| `hsts` | `bool` | Strict-Transport-Security present |
| `x_frame_options` | `string` | X-Frame-Options value |
| **TLS** | | |
| `certificate` | `{subject_cn: string, issuer_cn: string, issuer_org: string, serial_number: string, not_before: datetime, not_after: datetime, san_domains: string[], san_ips: string[], key_algorithm: string, key_size: int, signature_algorithm: string, is_self_signed: bool, is_expired: bool, is_wildcard: bool, fingerprint_sha256: string, transparency_logs: bool}` | TLS certificate serving this URL |
| **Discovery** | | |
| `screenshot_b64` | `string` | B64 of the screenshot |
| `cookies` | `{name: string, value: string, domain: string, secure: bool, httponly: bool, samesite: string}[]` | Cookies set |
| `robots_txt` | `string` | robots.txt content (if root URL) |
| `sitemap_urls` | `string[]` | URLs from sitemap.xml |
| **Virtual Hosting** | | |
| `vhosts` | `string[]` | Virtual hostnames resolved to this endpoint |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `hosted_on` | **Domain** / **IP Address** | Where this URL is hosted |

---

## 5. Email Address

> An email address found during recon.

### Identity
- **address** `string` — Full email (e.g. `john@example.com`)

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `local_part` | `string` | Part before @ |
| `domain` | `string` | Part after @ |
| **Validation** | | |
| `is_valid` | `bool` | Whether email is deliverable |
| `is_freemail` | `bool` | Gmail, Yahoo, etc. |
| `is_disposable` | `bool` | Temporary email service |
| `is_role` | `bool` | Role account (info@, admin@, ...) |
| `is_catchall` | `bool` | Domain accepts all addresses |
| `mx_records` | `string[]` | MX records for the domain |
| `smtp_check` | `bool` | SMTP verification result |
| **Person Info** (from OSINT enrichment) | | |
| `first_name` | `string` | First name |
| `last_name` | `string` | Last name |
| `full_name` | `string` | Full name |
| `avatar_url` | `string` | Profile picture URL |
| `phone` | `string` | Phone number |
| `bio` | `string` | Bio/description |
| `job_title` | `string` | Job title |
| `seniority` | `string` | Seniority level |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `belongs_to_domain` | **Domain** | Domain of the email |
| `has_username` | **Username** | Associated usernames |
| `has_social` | **Social Profile** | Social media profiles |
| `exposed_in` | **Leak** | Data breaches containing this email |
| `found_in_paste` | **Paste** | Paste sites containing this email |
| `belongs_to_org` | **Organisation** | Associated organisation |

---

## 6. Service

> A network service running on an IP at a specific port. Combines bbot's `OPEN_TCP_PORT`, `OPEN_UDP_PORT`, and `PROTOCOL` into one entity.

### Identity
- **endpoint** `string` — `ip:port/transport` (e.g. `93.184.216.34:443/tcp`)

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `ip` | `string` | IP address |
| `port` | `int` | Port number |
| `transport` | `enum: tcp, udp` | Transport protocol |
| **Service Detection** | | |
| `protocol` | `string` | Application protocol (HTTP, SSH, FTP, SMTP, ...) |
| `product` | `string` | Software product (OpenSSH, Apache, nginx, ...) |
| `version` | `string` | Product version |
| `banner` | `string` | Service banner |
| `cpes` | `string[]` | CPE identifiers |
| `os` | `string` | Detected OS (from service fingerprint) |
| **TLS/SSL** (if encrypted) | | |
| `tls_version` | `string` | TLS protocol version |
| `cipher_suite` | `string` | Negotiated cipher |
| `certificate` | `{subject_cn: string, issuer_cn: string, issuer_org: string, serial_number: string, not_before: datetime, not_after: datetime, san_domains: string[], san_ips: string[], key_algorithm: string, key_size: int, signature_algorithm: string, is_self_signed: bool, is_expired: bool, is_wildcard: bool, fingerprint_sha256: string, transparency_logs: bool}` | TLS certificate presented by this service |
| **Service Info** | | |
| `extra_info` | `string` | Additional service info |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `runs_on` | **IP Address** | Host IP |
| `serves` | **URL** | Web URLs served by this service |

---

## 9. Cloud Resource

> A cloud resource — storage buckets (S3, GCS, Azure Blob), cloud tenants, accounts, functions, etc. Generalizes bbot's `STORAGE_BUCKET` and `AZURE_TENANT`.

### Identity
- **resource_id** `string` — `provider:type:identifier` (e.g. `aws:s3:my-bucket`, `azure:tenant:contoso.onmicrosoft.com`)

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `provider` | `enum: aws, gcp, azure, digitalocean, other` | Cloud provider |
| `resource_type` | `enum: storage_bucket, tenant, account, function, database, vm, container_registry` | Resource type |
| `name` | `string` | Resource name |
| `url` | `string` | Access URL |
| `region` | `string` | Cloud region |
| `is_public` | `bool` | Publicly accessible |
| `permissions` | `string[]` | Discovered permissions (e.g. `LIST`, `READ`, `WRITE`) |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `owned_by` | **Organisation** | Owner |
| `associated_domain` | **Domain** | Related domains |
| `accessible_from` | **URL** | URLs that reference this resource |

---

## 10. Code Repository

> A source code repository (Git, SVN, etc.).

### Identity
- **url** `string` — Repository URL

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `platform` | `enum: github, gitlab, bitbucket, azure_devops, self_hosted` | Hosting platform |
| `owner` | `string` | Repo owner / org |
| `repo_name` | `string` | Repository name |
| `is_public` | `bool` | Publicly accessible |
| `language` | `string` | Primary language |
| `description` | `string` | Repo description |
| `default_branch` | `string` | Default branch |
| `stars` | `int` | Star count |
| `forks` | `int` | Fork count |
| `last_commit_date` | `datetime` | Last commit timestamp |
| `created_date` | `datetime` | Creation date |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `owned_by` | **Username** | Repository owner |
| `contains_secret` | **Secret** | Secrets found in code |
å
---

## 11. Username

> An online username / identity handle.

### Identity
- **name** `string` — The username

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `platforms` | `{platform: string, url: string, verified: bool}[]` | Platforms where this username exists |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `belongs_to` | **Email Address** | Associated email |
| `has_social` | **Social Profile** | Full social profiles |
| `exposed_in` | **Leak** | Data breaches |
| `owns_repo` | **Code Repository** | Code repositories |

---

## 12. Social Profile

> A social media profile. Consolidates hackermate's separate Twitter/LinkedIn/GitHub/Facebook nodes into one entity with platform-specific attributes.

### Identity
- **platform_handle** `string` — `platform:username` (e.g. `twitter:elonmusk`)

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `platform` | `enum: twitter, linkedin, facebook, github, instagram, reddit, telegram, youtube, mastodon, tiktok, other` | Platform name |
| `username` | `string` | Username on platform |
| `profile_url` | `string` | Full profile URL |
| `display_name` | `string` | Display / real name |
| `avatar_url` | `string` | Profile picture URL |
| `bio` | `string` | Bio / description |
| `location` | `string` | Listed location |
| `website` | `string` | Linked website |
| `verified` | `bool` | Verified account |
| `is_private` | `bool` | Private/protected account |
| `created_at` | `datetime` | Account creation date |
| **Metrics** | | |
| `followers` | `int` | Follower count |
| `following` | `int` | Following count |
| `posts_count` | `int` | Post / tweet count |
| **Platform-specific** | | |
| `company` | `string` | Company (GitHub, LinkedIn) |
| `blog` | `string` | Blog URL (GitHub) |
| `listed_count` | `int` | List count (Twitter) |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `belongs_to` | **Email Address** / **Username** | Owner |

---

## 13. Mobile App

> A mobile application (iOS / Android).

### Identity
- **store_id** `string` — `platform:bundle_id` (e.g. `android:com.example.app`)

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `platform` | `enum: ios, android` | Mobile platform |
| `bundle_id` | `string` | Bundle ID / package name |
| `name` | `string` | App name |
| `store_url` | `string` | App/Play Store URL |
| `developer` | `string` | Developer name |
| `version` | `string` | Latest version |
| `description` | `string` | App description |
| `permissions` | `string[]` | Requested permissions |

---

## 14. Vulnerability

> A security vulnerability found on an asset. Kept as a first-class entity because vulnerabilities have their own identity (CVE), lifecycle, and many-to-many relationships.

### Identity
- **dedupe_key** `string` — CVE ID, or hash of (host + description + type) for non-CVE vulns

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `string` | Vulnerability name/title |
| `severity` | `enum: critical, high, medium, low, info` | Severity rating |
| `cvss_score` | `float` | CVSS score (0.0-10.0) |
| `cve_id` | `string` | CVE identifier (if applicable) |
| `cwe_id` | `string` | CWE identifier |
| `description` | `string` | Detailed description |
| `solution` | `string` | Remediation guidance |
| `references` | `string[]` | Reference URLs |
| `cpes` | `string[]` | Affected CPE identifiers |
| `proof` | `string` | Evidence / proof of exploitation |
| `exploit_available` | `bool` | Known exploit exists |
| `verified` | `bool` | Manually verified |
| `detected_by` | `string` | Tool/module that found it |
| **Context** (where it was found) | | |
| `affected_host` | `string` | Host where found |
| `affected_url` | `string` | URL where found |
| `affected_port` | `int` | Port where found |
| `affected_parameter` | `string` | Parameter involved |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `affects` | **Domain** / **IP Address** / **URL** / **Service** | Affected asset(s) |

---

## 15. Secret

> A discovered credential, API key, token, or other sensitive value. Consolidates bbot's `PASSWORD`, `HASHED_PASSWORD`, and credential-related data.

### Identity
- **fingerprint** `string` — Hash of (type + value) for dedup without storing raw secrets

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `type` | `enum: password, hashed_password, api_key, token, private_key, connection_string, oauth_secret, jwt, other` | Secret type |
| `value` | `string` | The secret value (store encrypted / redacted in output) |
| `hash_algorithm` | `string` | Hash algorithm (for hashed_password: md5, sha1, bcrypt, ...) |
| `rule_name` | `string` | Detection rule (e.g. TruffleHog rule, Noseyparker rule) |
| `leak_name` | `string` | Name of the leak where the secret was found (if any) |
| `context_snippet` | `string` | Surrounding text for context |
| `confidence` | `enum: confirmed, probable, possible` | Detection confidence |
| **Source** | | |
| `source_url` | `string` | URL where found |
| `source_file` | `string` | File path where found |
| `source_line` | `int` | Line number |
| **Credential pair** | | |
| `username` | `string` | Associated username (if found together) |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `found_in` | **URL** / **Code Repository** / **File** | Where it was found |
| `belongs_to` | **Email Address** / **Username** | Owner of the credential |

---

## 17. Paste

> A paste site entry (Pastebin, Ghostbin, etc.) containing relevant data.

### Identity
- **url** `string` — Paste URL

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `source` | `string` | Paste site name |
| `title` | `string` | Paste title |
| `date` | `datetime` | Date posted |
| `content_preview` | `string` | Content preview / snippet |
| `length` | `int` | Content length |
| `tags` | `string[]` | Tags/labels |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `mentions` | **Email Address** / **Domain** / **IP Address** | Assets mentioned |
| `contains` | **Secret** | Secrets found in paste |

---

## 18. File

> A file or filesystem artifact discovered during scanning. From bbot's `FILESYSTEM` event.

### Identity
- **path_or_hash** `string` — File path or content hash

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `path` | `string` | File system path |
| `filename` | `string` | File name |
| `size` | `int` | File size in bytes |
| `mime_type` | `string` | MIME type |
| `magic_description` | `string` | Libmagic file type description |
| `extension` | `string` | File extension |
| `is_compressed` | `bool` | Compressed archive |
| `compression_type` | `string` | Compression format (zip, gzip, tar, ...) |
| `content_hash` | `string` | SHA-256 of file content |

### Relationships

| Relationship | Target | Description |
|---|---|---|
| `found_on` | **URL** / **IP Address** / **Code Repository** | Where the file was found |
| `contains_secret` | **Secret** | Secrets found in this file |
| `related_to` | **Domain** / **Email Address** | Entities referenced in file |

---

## Common Metadata (All Entities)

Every entity carries these meta-attributes, not part of the entity's domain model but essential for tooling:

| Meta-attribute | Type | Description |
|---|---|---|
| `id` | `string` | Unique identifier (type + identity key hash) |
| `entity_type` | `string` | Entity type name |
| `created_at` | `datetime` | When first discovered |
| `updated_at` | `datetime` | Last enrichment/update |
| `discovered_by` | `string[]` | Modules/tools that found or enriched this entity |

---

## Relationship Summary (Graph)

```
Domain ──resolves_to──▶ IP Address
Domain ──has_subdomain──▶ Domain
Domain ──cname_to──▶ Domain
Domain ──has_email──▶ Email Address
Domain ──hosts──▶ URL

IP Address ──in_range──▶ IP Range
IP Address ──runs──▶ Service
IP Address ──hosts──▶ URL

IP Range ──contains──▶ IP Address
IP Range ──subnet_of──▶ IP Range
IP Range ──has_subnet──▶ IP Range

URL ──hosted_on──▶ Domain / IP Address

Email Address ──belongs_to_domain──▶ Domain
Email Address ──has_username──▶ Username
Email Address ──has_social──▶ Social Profile
Email Address ──exposed_in──▶ Leak
Email Address ──found_in_paste──▶ Paste
Email Address ──belongs_to_org──▶ Organisation

Service ──runs_on──▶ IP Address
Service ──serves──▶ URL

Cloud Resource ──owned_by──▶ Organisation
Cloud Resource ──associated_domain──▶ Domain
Cloud Resource ──accessible_from──▶ URL

Code Repository ──owned_by──▶ Username
Code Repository ──contains_secret──▶ Secret

Username ──belongs_to──▶ Email Address
Username ──has_social──▶ Social Profile
Username ──exposed_in──▶ Leak
Username ──owns_repo──▶ Code Repository

Social Profile ──belongs_to──▶ Email Address / Username

Vulnerability ──affects──▶ Domain / IP Address / URL / Service

Secret ──found_in──▶ URL / Code Repository / File
Secret ──belongs_to──▶ Email Address / Username

Paste ──mentions──▶ Email Address / Domain / IP Address
Paste ──contains──▶ Secret

File ──found_on──▶ URL / IP Address / Code Repository
File ──contains_secret──▶ Secret
File ──related_to──▶ Domain / Email Address
```

---

## Migration Guide: bbot Events → New Entities

| bbot event | Maps to | Key change |
|---|---|---|
| `DNS_NAME` | **Domain** | Centralized DNS/WHOIS/cert/recon enrichment on one entity |
| `DNS_NAME_UNRESOLVED` | **Domain** (`is_resolved: false`) | Same entity, unresolved status as state |
| `RAW_DNS_RECORD` | **Domain** DNS attributes | Absorbed into typed DNS fields (`dns_a`, `dns_mx`, `dns_txt`, etc.) |
| `IP_ADDRESS` | **IP Address** | Geolocation/network/reputation moved to IP attributes |
| `IP_RANGE` | **IP Range** | Preserved as first-class network entity |
| `URL` | **URL** | Consolidates HTTP, technology, WAF, TLS, screenshot, cookies, and vhost data |
| `URL_UNVERIFIED` | **URL** (`is_verified: false`) | Same entity with verification state |
| `URL_HINT` | **URL** (`is_verified: false`, `confidence: low`) | Same entity with low-confidence discovery state |
| `HTTP_RESPONSE` | **URL** attributes | Response details absorbed into URL (`status_code`, headers, body hash, etc.) |
| `WAF` | **URL**.`waf` attribute | No standalone WAF entity |
| `TECHNOLOGY` | **URL**.`technologies[]` or **Service** (`product`/`version`) | Technology becomes enrichment on the affected asset |
| `VHOST` | **URL**.`vhosts[]` attribute | Virtual hosts stored as URL hosting metadata |
| `WEBSCREENSHOT` | **URL**.`screenshot_b64` attribute | Screenshot stored as URL discovery artifact |
| `GEOLOCATION` | **IP Address** geo attributes | Location data attached to IP entity |
| `OPEN_TCP_PORT` | **Service** (`transport: tcp`) | Port/protocol/product merged into one service entity |
| `OPEN_UDP_PORT` | **Service** (`transport: udp`) | UDP follows same service model |
| `PROTOCOL` | **Service**.`protocol` attribute | Protocol is a service property, not an entity |
| `EMAIL_ADDRESS` | **Email Address** | Validation and person-level enrichment in one entity |
| `USERNAME` | **Username** | Consolidated identity handle with cross-platform links |
| `SOCIAL` | **Social Profile** | Platform-specific profiles unified under one entity type |
| `PASSWORD` | **Secret** (`type: password`) | Credentials become first-class secrets |
| `HASHED_PASSWORD` | **Secret** (`type: hashed_password`) | Hash metadata preserved on Secret |
| `VULNERABILITY` | **Vulnerability** | Keeps CVE/CWE/CVSS/proof/context in a dedicated entity |
| `FINDING` | Removed — use **Vulnerability** or entity attributes | No generic catch-all object |
| `STORAGE_BUCKET` | **Cloud Resource** (`resource_type: storage_bucket`) | Bucket-specific events normalized under cloud resources |
| `AZURE_TENANT` | **Cloud Resource** (`resource_type: tenant`) | Tenant events normalized under cloud resources |
| `CODE_REPOSITORY` | **Code Repository** | Enriched repo metadata plus links to owner/secrets |
| `MOBILE_APP` | **Mobile App** | Store/package identity and metadata in one entity |
| `ASN` | **ASN** entity and/or ASN attributes on **IP Address**/**IP Range** | Normalized ASN data replaces raw dict-style payloads |
| `FILESYSTEM` | **File** | File artifacts become structured file entities |
| `RAW_TEXT` | Intermediate artifact (not persisted) | Parsing/input helper, not a final entity |
| `SCAN` / `FINISHED` | Lifecycle events (not entities) | Execution state, not attack-surface data |
