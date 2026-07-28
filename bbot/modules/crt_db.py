import asyncio
import time
import asyncpg

from bbot.modules.templates.subdomain_enum import subdomain_enum


class crt_db(subdomain_enum):
    flags = ["subdomain-enum", "passive", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["DNS_NAME"]
    meta = {
        "description": "Query crt.sh (certificate transparency) for subdomains via PostgreSQL",
        "created_date": "2025-03-27",
        "author": "@TheTechromancer",
    }

    deps_pip = ["asyncpg"]

    db_host = "crt.sh"
    db_port = 5432
    db_user = "guest"
    db_name = "certwatch"
    base_url = "https://crt.sh"
    certspotter_url = "https://api.certspotter.com/v1"

    async def setup(self):
        self.db_conn = None
        self.cert_ids = set()
        return await super().setup()

    async def fallback_request_url(self, query):
        certspotter = (
            f"{self.certspotter_url}/issuances"
            f"?domain={self.helpers.quote(query)}&include_subdomains=true&expand=dns_names"
        )
        self.verbose(f'crt_db falling back to CertSpotter for "{query}"')
        return await self.api_request(certspotter, timeout=self.http_timeout + 30)

    async def _connect(self):
        if self.db_conn is None or self.db_conn.is_closed():
            self.db_conn = await asyncio.wait_for(
                asyncpg.connect(
                    host=self.db_host,
                    port=self.db_port,
                    user=self.db_user,
                    database=self.db_name,
                    statement_cache_size=0,  # Disable automatic statement preparation
                    timeout=10,
                    command_timeout=20,
                ),
                timeout=12,
            )

    async def _reconnect(self):
        if self.db_conn is not None:
            try:
                await self.db_conn.close()
            except Exception:
                pass
        self.db_conn = None
        await self._connect()

    async def request_url(self, query):
        try:
            await self._connect()
        except (asyncio.TimeoutError, TimeoutError, OSError):
            self.verbose("crt.sh DB connection timed out")
            return await self.fallback_request_url(query)

        sql = """
        WITH ci AS (
            SELECT array_agg(DISTINCT sub.NAME_VALUE) NAME_VALUES
            FROM (
                SELECT DISTINCT cai.CERTIFICATE, cai.NAME_VALUE
                FROM certificate_and_identities cai
                WHERE plainto_tsquery('certwatch', $1) @@ identities(cai.CERTIFICATE)
                    AND cai.NAME_VALUE ILIKE ('%.' || $1)
                LIMIT 50000
            ) sub
            GROUP BY sub.CERTIFICATE
        )
        SELECT DISTINCT unnest(NAME_VALUES) as name_value FROM ci;
        """
        start = time.time()
        try:
            results = await asyncio.wait_for(self.db_conn.fetch(sql, query), timeout=20)
        except asyncpg.OutOfMemoryError as e:
            self.set_error_state(f"crt.sh Postgres reported out-of-memory: {e}")
            return []
        except (
            asyncpg.InterfaceError,
            asyncpg.ConnectionDoesNotExistError,
            asyncio.TimeoutError,
            TimeoutError,
            OSError,
        ):
            self.verbose("crt.sh DB connection dropped, reconnecting")
            try:
                await self._reconnect()
                results = await asyncio.wait_for(self.db_conn.fetch(sql, query), timeout=20)
            except (asyncio.TimeoutError, TimeoutError, OSError):
                self.verbose("crt.sh DB reconnect timed out")
                return await self.fallback_request_url(query)
        end = time.time()
        self.verbose(f"SQL query executed in: {end - start} seconds with {len(results):,} results")
        return results

    async def parse_results(self, results, query):
        domains = set()
        if hasattr(results, "json"):
            try:
                json_data = results.json()
            except Exception:
                return domains
            if not isinstance(json_data, list):
                return domains
            for cert_info in json_data:
                if not isinstance(cert_info, dict):
                    continue
                dns_names = cert_info.get("dns_names")
                if isinstance(dns_names, list):
                    for domain in dns_names:
                        if not isinstance(domain, str):
                            continue
                        d = domain.lower().strip().rstrip(".")
                        while d.startswith("*."):
                            d = d[2:]
                        while d.startswith("_wildcard."):
                            d = d[len("_wildcard.") :]
                        if d:
                            domains.add(d)
                    continue
                cert_id = cert_info.get("id")
                if cert_id:
                    cert_hash = hash(cert_id)
                    if cert_hash in self.cert_ids:
                        continue
                    self.cert_ids.add(cert_hash)
                domain = cert_info.get("name_value")
                if not domain:
                    continue
                for d in domain.splitlines():
                    d = d.lower().strip().rstrip(".")
                    while d.startswith("*."):
                        d = d[2:]
                    while d.startswith("_wildcard."):
                        d = d[len("_wildcard.") :]
                    if d:
                        domains.add(d)
            return domains

        for row in results:
            dns_names = row.get("dns_names") if hasattr(row, "get") else None
            if isinstance(dns_names, list):
                for domain in dns_names:
                    if not isinstance(domain, str):
                        continue
                    d = domain.lower().strip().rstrip(".")
                    while d.startswith("*."):
                        d = d[2:]
                    while d.startswith("_wildcard."):
                        d = d[len("_wildcard.") :]
                    if d:
                        domains.add(d)
                continue
            domain = row["name_value"]
            if domain:
                for d in domain.splitlines():
                    d = d.lower().strip().rstrip(".")
                    while d.startswith("*."):
                        d = d[2:]
                    while d.startswith("_wildcard."):
                        d = d[len("_wildcard.") :]
                    if d:
                        domains.add(d)
        return domains

    async def cleanup(self):
        if self.db_conn:
            await self.db_conn.close()
