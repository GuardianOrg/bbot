import re
from collections import defaultdict

from bbot.modules.templates.subdomain_enum import subdomain_enum_apikey


PER_PARENT_CAP = 300
PTR_NOISE_PATTERNS = [
    re.compile(r"^\d{1,3}(\.\d{1,3}){3}(\.|$)"),
    re.compile(r"^\d{1,3}(-\d{1,3}){3}(\.|$|-)"),
]


def _collapse(subdomains, domain, query):
    """Filter PTR-style names and collapse unusably large sibling floods."""
    prefixes = []
    for subdomain in subdomains:
        subdomain = str(subdomain).lower().strip(".*")
        if not subdomain or any(pattern.match(subdomain) for pattern in PTR_NOISE_PATTERNS):
            continue
        prefixes.append(subdomain)

    suffix = f".{query}"
    fqdns = []
    for prefix in prefixes:
        full_name = f"{prefix}.{domain}"
        if full_name.endswith(suffix):
            fqdns.append(full_name)

    parent_children = defaultdict(set)
    for name in fqdns:
        _, parent = name.split(".", 1)
        parent_children[parent].add(name)

    results = set()
    capped = []
    for parent, children in parent_children.items():
        if len(children) > PER_PARENT_CAP and parent != query:
            capped.append((parent, len(children)))
            results.add(parent)
        else:
            results.update(children)
    return results, capped


class chaos(subdomain_enum_apikey):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query ProjectDiscovery's Chaos API for subdomains",
        "created_date": "2022-08-14",
        "author": "@TheTechromancer",
        "auth_required": True,
    }
    options = {"api_key": ""}
    options_desc = {"api_key": "Chaos API key"}

    base_url = "https://dns.projectdiscovery.io/dns"
    ping_url = f"{base_url}/example.com"

    def prepare_api_request(self, url, kwargs):
        kwargs["headers"]["Authorization"] = self.api_key
        return url, kwargs

    async def request_url(self, query):
        _, domain = self.helpers.split_domain(query)
        url = f"{self.base_url}/{domain}/subdomains"
        return await self.api_request(url)

    async def parse_results(self, r, query):
        j = r.json()
        if not isinstance(j, dict):
            return set()
        domain = j.get("domain", "")
        subdomains = j.get("subdomains") or []
        if not domain or not isinstance(subdomains, (list, tuple, set)) or not subdomains:
            return set()
        results, capped = await self.helpers.run_in_executor_mp(_collapse, subdomains, domain, query)
        for parent, count in capped:
            self.verbose(
                f"chaos returned {count:,} children of {parent}, above the per-parent cap "
                f"of {PER_PARENT_CAP}; emitting the parent only"
            )
        return results
