import json
import ipaddress
from urllib.parse import urljoin, urlparse

from bbot.modules.templates.subdomain_enum import subdomain_enum


class dnsdumpster(subdomain_enum):
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME", "DOMAIN_DNS_HISTORY"]
    flags = ["subdomain-enum", "passive", "safe"]
    meta = {
        "description": "Query dnsdumpster for subdomains",
        "created_date": "2022-03-12",
        "author": "@TheTechromancer",
    }

    base_url = "https://dnsdumpster.com"

    async def setup(self):
        self.apikey_regex = self.helpers.re.compile(r'<form[^>]*data-form-id="mainform"[^>]*hx-headers=\'([^\']*)\'')
        self.endpoint_regex = self.helpers.re.compile(r'<form[^>]*data-form-id="mainform"[^>]*hx-post="([^"]+)"')
        return True

    async def query(self, domain):
        names, _ = await self.query_with_records(domain)
        return names

    async def handle_event(self, event):
        query = self.make_query(event)
        names, histories = await self.query_with_records(query)
        for hostname in sorted(set(names)):
            try:
                hostname = self.helpers.validators.validate_host(hostname)
            except ValueError as error:
                self.verbose(error)
                continue
            if hostname != event.data and hostname.endswith(f".{query}"):
                await self.emit_event(
                    hostname,
                    "DNS_NAME",
                    event,
                    abort_if=self.abort_if,
                    context=f'{{module}} searched DNSDumpster for "{query}" and found {{event.type}}: {{event.data}}',
                )
        for host, records in sorted(histories.items()):
            await self.emit_event(
                {"host": host, "records": records},
                "DOMAIN_DNS_HISTORY",
                event,
                context=f'{{module}} found A/AAAA records for "{host}" in DNSDumpster: {{event.type}}',
            )

    async def query_with_records(self, domain):
        res1 = await self.api_request(self.base_url)
        status_code = getattr(res1, "status_code", 0)
        if status_code not in [200]:
            self.verbose(f'Bad response code "{status_code}" from DNSDumpster')
            return [], {}

        # The public page now posts to /htmld/ without a token. Older pages use
        # api.dnsdumpster.com and a short-lived Authorization token.
        endpoint_match = await self.helpers.re.search(self.endpoint_regex, res1.text)
        if not endpoint_match:
            self.warning("DNSDumpster result endpoint was not found in the public form")
            return [], {}
        endpoint = urljoin(self.base_url, endpoint_match.group(1))
        if urlparse(endpoint).hostname not in ("dnsdumpster.com", "api.dnsdumpster.com"):
            self.warning("DNSDumpster public form advertised an unexpected endpoint")
            return [], {}

        jwt_token = None
        try:
            form_match = await self.helpers.re.search(self.apikey_regex, res1.text)
            if form_match:
                headers_json = form_match.group(1)
                headers_data = json.loads(headers_json)
                jwt_token = headers_data.get("Authorization")
        except (AttributeError, json.JSONDecodeError, KeyError):
            self.warning("DNSDumpster public form contains invalid request headers")
            return [], {}
        if urlparse(endpoint).hostname == "api.dnsdumpster.com" and not jwt_token:
            self.warning("DNSDumpster API endpoint requires a token absent from the public form")
            return [], {}

        if self.scan.stopping:
            return [], {}

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://dnsdumpster.com",
            "Referer": "https://dnsdumpster.com/",
            "HX-Request": "true",
            "HX-Target": "results",
            "HX-Current-URL": "https://dnsdumpster.com/",
        }
        if jwt_token:
            headers["Authorization"] = jwt_token
        res2 = await self.api_request(
            endpoint,
            method="POST",
            data={"target": str(domain).lower()},
            headers=headers,
        )
        status_code = getattr(res2, "status_code", 0)
        if status_code not in [200]:
            self.verbose(f'Bad response code "{status_code}" from DNSDumpster API')
            return [], {}

        names = await self.scan.extract_in_scope_hostnames(res2.text)
        return names, self.parse_address_records(res2.text, domain)

    def parse_address_records(self, html, domain):
        soup = self.helpers.beautifulsoup(html, "html.parser")
        if soup is False:
            return {}
        histories = {}
        for record_type, table_id in (("A", "a_rec_table"), ("AAAA", "aaaa_rec_table")):
            table = soup.find("table", id=table_id)
            if table is None:
                continue
            headings = [cell.get_text(" ", strip=True).lower() for cell in table.find_all("th")]
            for row in table.find_all("tr"):
                cells = row.find_all("td", recursive=False)
                if len(cells) < 2:
                    continue
                host = cells[0].get_text(" ", strip=True).lower().rstrip(".")
                address = cells[1].get_text(" ", strip=True).split(" ", 1)[0]
                if host != domain and not host.endswith(f".{domain}"):
                    continue
                try:
                    ip = ipaddress.ip_address(address)
                except ValueError:
                    continue
                if (record_type == "A") != (ip.version == 4):
                    continue
                record = {"ip": address, "record_type": record_type, "source": "dnsdumpster"}
                for field in ("first_seen", "last_seen"):
                    heading = field.replace("_", " ")
                    if heading in headings:
                        value = cells[headings.index(heading)].get_text(" ", strip=True)
                        if value:
                            record[field] = value
                histories.setdefault(host, []).append(record)
        return histories
