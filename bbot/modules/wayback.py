import asyncio
import json
from datetime import datetime

from bbot.modules.templates.subdomain_enum import subdomain_enum


class wayback(subdomain_enum):
    flags = ["passive", "subdomain-enum", "safe"]
    watched_events = ["DNS_NAME"]
    produced_events = ["URL_UNVERIFIED", "DNS_NAME"]
    meta = {
        "description": "Query archive.org's API for subdomains",
        "created_date": "2022-04-01",
        "author": "@liquidsec",
    }
    options = {"urls": True, "garbage_threshold": 10, "max_urls": 5000, "retry_attempts": 3, "retry_sleep": 10}
    options_desc = {
        "urls": "emit URLs in addition to DNS_NAMEs",
        "garbage_threshold": "Dedupe similar urls if they are in a group of this size or higher (lower values == less garbage data)",
        "max_urls": "Maximum number of archived URLs to collapse per query",
        "retry_attempts": "Number of archive.org fetch attempts before giving up",
        "retry_sleep": "Seconds to sleep between retry attempts when archive.org returns no data",
    }
    in_scope_only = True

    base_url = "https://web.archive.org"

    async def setup(self):
        self.urls = self.config.get("urls", False)
        self.garbage_threshold = self.config.get("garbage_threshold", 10)
        self.max_urls = int(self.config.get("max_urls", 5000))
        self.retry_attempts = max(1, int(self.config.get("retry_attempts", 3)))
        self.retry_sleep = max(0, int(self.config.get("retry_sleep", 10)))
        return await super().setup()

    async def handle_event(self, event):
        query = self.make_query(event)
        for result, event_type in await self.query(query):
            await self.emit_event(
                result,
                event_type,
                event,
                abort_if=self.abort_if,
                context=f'{{module}} queried archive.org for "{query}" and found {{event.type}}: {{event.data}}',
            )

    async def query(self, query):
        results = set()
        waybackurl = f"{self.base_url}/cdx/search/cdx?url={self.helpers.quote(query)}&matchType=domain&output=json&fl=original&collapse=original"
        urls = []
        for attempt in range(1, self.retry_attempts + 1):
            try:
                result = await asyncio.wait_for(
                    self.run_process(
                        [
                            "curl",
                            "--fail",
                            "--silent",
                            "--show-error",
                            "--location",
                            "--max-time",
                            str(self.http_timeout + 10),
                            waybackurl,
                        ],
                        _log_stderr=False,
                        check=False,
                    ),
                    timeout=self.http_timeout + 15,
                )
            except (TimeoutError, asyncio.TimeoutError):
                self.warning(f'Error connecting to archive.org for query "{query}" on attempt {attempt}/{self.retry_attempts}')
                if attempt < self.retry_attempts and self.retry_sleep > 0:
                    await self.helpers.sleep(self.retry_sleep)
                continue
            if not result or result.returncode != 0:
                self.warning(f'Error connecting to archive.org for query "{query}" on attempt {attempt}/{self.retry_attempts}')
                if attempt < self.retry_attempts and self.retry_sleep > 0:
                    await self.helpers.sleep(self.retry_sleep)
                continue
            try:
                j = json.loads(result.stdout)
                assert type(j) == list
            except Exception:
                self.warning(f'Error JSON-decoding archive.org response for query "{query}" on attempt {attempt}/{self.retry_attempts}')
                if attempt < self.retry_attempts and self.retry_sleep > 0:
                    await self.helpers.sleep(self.retry_sleep)
                continue

            urls = []
            for result in j[1:]:
                try:
                    url = result[0]
                    urls.append(url)
                except KeyError:
                    continue

            if urls or attempt >= self.retry_attempts:
                break

            self.debug(
                f'No results from archive.org for "{query}" on attempt {attempt}/{self.retry_attempts}; retrying in {self.retry_sleep}s'
            )
            if self.retry_sleep > 0:
                await self.helpers.sleep(self.retry_sleep)

        self.verbose(f"Found {len(urls):,} URLs for {query}")
        if self.max_urls > 0 and len(urls) > self.max_urls:
            self.verbose(f"Limiting {query} archive URLs from {len(urls):,} to {self.max_urls:,} before collapsing")
            urls = urls[: self.max_urls]

        dns_names = set()
        collapsed_urls = 0
        start_time = datetime.now()
        # we consolidate URLs to cut down on garbage data
        # this is CPU-intensive, so we do it in its own core.
        parsed_urls = await self.helpers.run_in_executor_mp(
            self.helpers.validators.collapse_urls,
            urls,
            threshold=self.garbage_threshold,
        )
        for parsed_url in parsed_urls:
            collapsed_urls += 1
            if not self.urls:
                dns_name = parsed_url.hostname
                h = hash(dns_name)
                if h not in dns_names:
                    dns_names.add(h)
                    results.add((dns_name, "DNS_NAME"))
            else:
                results.add((parsed_url.geturl(), "URL_UNVERIFIED"))
        end_time = datetime.now()
        duration = self.helpers.human_timedelta(end_time - start_time)
        self.verbose(f"Collapsed {len(urls):,} -> {collapsed_urls:,} URLs in {duration}")
        return results
