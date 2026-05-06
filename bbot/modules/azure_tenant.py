from bbot.modules.base import BaseModule
import xml.etree.ElementTree as ET
from urllib.parse import quote
import re


class azure_tenant(BaseModule):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["affiliates", "subdomain-enum", "cloud-enum", "passive", "safe"]
    meta = {
        "description": "Query Azure via azmap.dev for tenant sister domains",
        "created_date": "2024-07-04",
        "author": "@TheTechromancer",
    }

    base_url = "https://azmap.dev/api/tenant"
    in_scope_only = True
    per_domain_only = True

    async def setup(self):
        self.processed = set()
        return True

    async def handle_event(self, event):
        _, event_domain = self.helpers.split_domain(event.data)
        domain_hash = hash(event_domain)
        if domain_hash in self.processed:
            return
        self.processed.add(domain_hash)

        _, registered_domain = self.helpers.split_domain(event.data)
        query_candidates = []
        for candidate in (str(event.data).lower(), registered_domain.lower()):
            if candidate and candidate not in query_candidates:
                query_candidates.append(candidate)

        tenant_data = {}
        query = query_candidates[0]
        for candidate in query_candidates:
            query = candidate
            tenant_data = await self.query(candidate)
            if tenant_data:
                break

        if not tenant_data:
            return

        tenant_id = tenant_data.get("tenant_id")
        tenant_name = tenant_data.get("tenant_name")
        email_domains = tenant_data.get("email_domains", [])
        source = tenant_data.get("_source", "azmap.dev")

        realm_info = {}
        dns_evidence = {}
        if not self.should_emit_tenant(query, tenant_id, realm_info, email_domains, dns_evidence):
            realm_info = await self.query_user_realm(query)
            dns_evidence = await self.query_dns_evidence(query)
            if not self.should_emit_tenant(query, tenant_id, realm_info, email_domains, dns_evidence):
                self.verbose(f'Skipping azure_tenant result for "{query}" because tenant evidence was too weak')
                return

        if email_domains:
            self.verbose(
                f'Found {len(email_domains):,} domains under tenant for "{query}": {", ".join(sorted(email_domains))}'
            )
            for domain in email_domains:
                if domain != query:
                    await self.emit_event(
                        domain,
                        "DNS_NAME",
                        parent=event,
                        tags=["affiliate", "azure-tenant"],
                        context=f'{{module}} queried azmap.dev for "{query}" and found {{event.type}}: {{event.data}}',
                    )

            # Build tenant names list (include the tenant name from the API)
            tenant_names = []
            if tenant_name:
                tenant_names.append(tenant_name)

            # Also extract tenant names from .onmicrosoft.com domains
            for domain in email_domains:
                if domain.lower().endswith(".onmicrosoft.com"):
                    tenantname = domain.split(".")[0].lower()
                    if tenantname and tenantname not in tenant_names:
                        tenant_names.append(tenantname)

            event_data = {"tenant-names": tenant_names, "domains": sorted(email_domains), "is_entraid_workspace": True}
            tenant_names_str = ",".join(tenant_names)
            if tenant_id:
                event_data["tenant-id"] = tenant_id
            await self.emit_event(
                event_data,
                "AZURE_TENANT",
                parent=event,
                context=f'{{module}} queried {source} for "{query}" and found {{event.type}}: {tenant_names_str}',
            )

    async def query(self, domain):
        url = f"{self.base_url}?domain={domain}&extract=true"

        self.debug(f"Retrieving tenant domains at {url}")

        r = await self.helpers.request(url)
        status_code = getattr(r, "status_code", 0)
        if status_code == 200:
            try:
                tenant_data = r.json()
            except Exception as e:
                self.warning(f'Error parsing JSON response for "{domain}": {e}')
                tenant_data = {}
            if tenant_data:
                return self.normalize_tenant_data(domain, {**tenant_data, "_source": "azmap.dev"})

        self.verbose(f'Error retrieving azure_tenant domains for "{domain}" from azmap.dev (status code: {status_code}), falling back to Microsoft endpoints')
        return await self.query_microsoft_endpoints(domain)

    def normalize_tenant_data(self, domain, tenant_data):
        email_domains = tenant_data.get("email_domains", [])
        for d in email_domains:
            d = str(d).lower()
            _, query = self.helpers.split_domain(d)
            self.processed.add(hash(query))
            self.scan.word_cloud.absorb_word(d)

        return tenant_data

    async def query_microsoft_endpoints(self, domain):
        tenant_id = await self.query_openid_tenant_id(domain)
        realm_info = await self.query_user_realm(domain)
        email_domains = await self.query_autodiscover_domains(domain)
        if not tenant_id and not email_domains:
            return {}

        if domain not in email_domains:
            email_domains.append(domain)

        tenant_names = []
        for email_domain in email_domains:
            if email_domain.lower().endswith(".onmicrosoft.com"):
                tenant_name = email_domain.split(".")[0].lower()
                if tenant_name and tenant_name not in tenant_names:
                    tenant_names.append(tenant_name)
        realm_brand = str((realm_info or {}).get("FederationBrandName", "")).strip()
        if realm_brand and realm_brand.lower() != "default directory" and realm_brand.lower() not in tenant_names:
            tenant_names.append(realm_brand.lower())

        tenant_data = {
            "tenant_id": tenant_id,
            "tenant_name": tenant_names[0] if tenant_names else "",
            "domain": domain,
            "email_domains": sorted(set(email_domains)),
            "_source": "microsoft-autodiscover-openid",
        }
        return self.normalize_tenant_data(domain, tenant_data)

    async def query_user_realm(self, domain):
        url = f"https://login.microsoftonline.com/getuserrealm.srf?login=test@{quote(domain)}"
        self.debug(f"Retrieving user realm information at {url}")
        r = await self.helpers.request(url)
        if getattr(r, "status_code", 0) != 200:
            return {}
        try:
            data = r.json()
        except Exception as e:
            self.warning(f'Error parsing user realm response for "{domain}": {e}')
            return {}
        return data if isinstance(data, dict) else {}

    async def query_dns_evidence(self, domain):
        evidence = {
            "has_ms_verification": False,
            "has_outlook_mx": False,
            "has_outlook_spf": False,
        }

        txt_results = await self.helpers.resolve_raw(domain, type="TXT")
        if txt_results:
            raw_results, _errors = txt_results
            for answer in raw_results:
                value = answer.to_text().strip('"').strip().lower().replace('" "', "")
                if value.startswith("ms="):
                    evidence["has_ms_verification"] = True
                if "include:spf.protection.outlook.com" in value:
                    evidence["has_outlook_spf"] = True

        mx_results = await self.helpers.resolve_raw(domain, type="MX")
        if mx_results:
            raw_results, _errors = mx_results
            for answer in raw_results:
                value = answer.to_text().strip().lower()
                if ".mail.protection.outlook.com" in value:
                    evidence["has_outlook_mx"] = True

        return evidence

    def should_emit_tenant(self, domain, tenant_id, realm_info, email_domains, dns_evidence):
        if not tenant_id:
            return False

        domain = str(domain or "").strip().lower()
        email_domains = [str(d).strip().lower() for d in (email_domains or []) if str(d).strip()]
        namespace = str((realm_info or {}).get("NameSpaceType", "")).strip().lower()

        if domain.endswith(".onmicrosoft.com"):
            return True

        if any(d.endswith(".onmicrosoft.com") for d in email_domains):
            return True

        if len(set(email_domains)) > 1:
            return True

        if namespace == "managed":
            return True

        return bool(
            dns_evidence.get("has_ms_verification")
            or dns_evidence.get("has_outlook_mx")
            or dns_evidence.get("has_outlook_spf")
        )

    async def query_openid_tenant_id(self, domain):
        url = f"https://login.microsoftonline.com/{quote(domain)}/.well-known/openid-configuration"
        self.debug(f"Retrieving tenant OpenID configuration at {url}")
        r = await self.helpers.request(url)
        if getattr(r, "status_code", 0) != 200:
            return None
        try:
            data = r.json()
        except Exception as e:
            self.warning(f'Error parsing OpenID configuration for "{domain}": {e}')
            return None

        issuer = str(data.get("issuer", ""))
        if issuer:
            match = re.search(r"/([0-9a-fA-F-]{36})/?$", issuer)
            if match:
                return match.group(1)

        token_endpoint = str(data.get("token_endpoint", ""))
        match = re.search(r"/([0-9a-fA-F-]{36})/oauth2", token_endpoint)
        if match:
            return match.group(1)
        return None

    async def query_autodiscover_domains(self, domain):
        url = "https://autodiscover-s.outlook.com/autodiscover/autodiscover.svc"
        envelope = f"""<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:exm="http://schemas.microsoft.com/exchange/services/2006/messages"
               xmlns:ext="http://schemas.microsoft.com/exchange/services/2006/types"
               xmlns:a="http://www.w3.org/2005/08/addressing"
               xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"
               xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
               xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <soap:Header>
    <a:Action soap:mustUnderstand="1">http://schemas.microsoft.com/exchange/2010/Autodiscover/Autodiscover/GetFederationInformation</a:Action>
    <a:To soap:mustUnderstand="1">{url}</a:To>
    <a:ReplyTo>
      <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>
    </a:ReplyTo>
  </soap:Header>
  <soap:Body>
    <GetFederationInformationRequestMessage xmlns="http://schemas.microsoft.com/exchange/2010/Autodiscover">
      <Request>
        <Domain>{domain}</Domain>
      </Request>
    </GetFederationInformationRequestMessage>
  </soap:Body>
</soap:Envelope>"""
        headers = {"Content-Type": "text/xml; charset=utf-8", "User-Agent": "BBOT-AzureTenant"}
        self.debug(f"Retrieving autodiscover federation information at {url} for {domain}")
        r = await self.helpers.request(url, method="POST", data=envelope.encode(), headers=headers)
        if getattr(r, "status_code", 0) != 200:
            return []

        try:
            root = ET.fromstring(r.text)
        except Exception as e:
            self.warning(f'Error parsing autodiscover response for "{domain}": {e}')
            return []

        domains = []
        for node in root.iter():
            if not str(node.tag).endswith("Domain"):
                continue
            value = (node.text or "").strip().lower()
            if value:
                domains.append(value)
        return sorted(set(domains))
