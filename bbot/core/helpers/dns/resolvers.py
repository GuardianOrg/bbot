"""Bounded DNS-only resolver validation and result confirmation."""

import asyncio
import ipaddress
import time
import secrets
import statistics

import dns.asyncquery
import dns.exception
import dns.flags
import dns.message
import dns.rcode
import dns.rdatatype

from bbot.errors import DNSError


class ResolverPool:
    defaults = ("1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4")
    controls = (
        ("one.one.one.one", "A", {"1.1.1.1", "1.0.0.1"}),
        ("one.one.one.one", "AAAA", {"2606:4700:4700::1111", "2606:4700:4700::1001"}),
        ("dns.google", "A", {"8.8.8.8", "8.8.4.4"}),
    )

    def __init__(self, timeout=1, max_runtime=10, concurrency=32):
        self.timeout = timeout
        self.max_runtime = max_runtime
        self.semaphore = asyncio.Semaphore(concurrency)
        self.selected = []
        self.measurements = []
        self.confirmations = 0
        self.rejected = 0

    @staticmethod
    def endpoint(value):
        value = str(value).strip()
        try:
            return str(ipaddress.ip_address(value)), 53
        except ValueError:
            host, port = value.rsplit(":", 1)
            host = str(ipaddress.ip_address(host.strip("[]")))
            port = int(port)
            if not 0 < port < 65536:
                raise ValueError("invalid DNS port")
            return host, port

    async def query(self, endpoint, host, kind):
        address, port = self.endpoint(endpoint)
        request = dns.message.make_query(host, kind)
        async with self.semaphore:
            response = await dns.asyncquery.udp(request, address, port=port, timeout=self.timeout)
            if response.flags & dns.flags.TC:
                response = await dns.asyncquery.tcp(request, address, port=port, timeout=self.timeout)
        return response

    async def validate_one(self, endpoint):
        elapsed = []
        try:
            for host, kind, expected in self.controls:
                started = time.monotonic()
                response = await self.query(endpoint, host, kind)
                elapsed.append(time.monotonic() - started)
                actual = {
                    str(record)
                    for rrset in response.answer
                    if rrset.rdtype == dns.rdatatype.from_text(kind) and str(rrset.name).lower().rstrip(".") == host
                    for record in rrset
                }
                if response.rcode() != dns.rcode.NOERROR or actual != expected:
                    return None
            for _ in range(2):
                response = await self.query(endpoint, f"{secrets.token_hex(12)}.invalid", "A")
                if response.rcode() != dns.rcode.NXDOMAIN or response.answer:
                    return None
        except (dns.exception.DNSException, OSError, ValueError):
            return None
        return {"endpoint": endpoint, "latency_ms": round(statistics.median(elapsed) * 1000, 2)}

    async def validate(self, candidates, fallback=()):
        deadline = time.monotonic() + self.max_runtime

        async def check(values):
            tasks = [asyncio.create_task(self.validate_one(value)) for value in dict.fromkeys(values)]
            try:
                done, pending = (
                    await asyncio.wait(tasks, timeout=max(0, deadline - time.monotonic())) if tasks else (set(), set())
                )
                return [result for task in done if (result := task.result()) is not None]
            finally:
                for task in tasks:
                    if not task.done():
                        task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

        measurements = await check(candidates)
        if not measurements:
            measurements = await check(fallback)
        if not measurements:
            raise DNSError(
                "No DNS resolver passed A/AAAA and NXDOMAIN controls; configure a reachable trusted resolver"
            )
        self.measurements = sorted(measurements, key=lambda item: (item["latency_ms"], item["endpoint"]))
        self.selected = [item["endpoint"] for item in self.measurements]
        return self.selected

    async def confirm(self, host, kind):
        # Prefer another provider when possible; the second resolver also recovers
        # transient transport failures. Never accept a timeout as negative evidence.
        choices = self.selected[:2]
        if self.selected and self.selected[0] in self.defaults:
            provider = "cloudflare" if self.selected[0].startswith("1.") else "google"
            other = next(
                (
                    value
                    for value in self.selected
                    if ("cloudflare" if value.startswith("1.") else "google") != provider
                ),
                None,
            )
            if other:
                choices = [other, self.selected[0]]
        for endpoint in choices:
            self.confirmations += 1
            try:
                response = await self.query(endpoint, host, kind)
            except (dns.exception.DNSException, OSError):
                continue
            if response.rcode() not in (dns.rcode.NOERROR, dns.rcode.NXDOMAIN):
                continue
            owner = host.lower().rstrip(".")
            for rrset in response.answer:
                if str(rrset.name).lower().rstrip(".") != owner:
                    continue
                valid_types = (
                    (dns.rdatatype.CNAME,)
                    if response.rcode() == dns.rcode.NXDOMAIN
                    else (dns.rdatatype.from_text(kind), dns.rdatatype.CNAME)
                )
                if rrset.rdtype in valid_types and len(rrset):
                    return True
        self.rejected += 1
        return False
