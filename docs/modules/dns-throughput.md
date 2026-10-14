# DNS throughput and resolver quality

Default discovery now has a shared 7,200-second elapsed deadline and 400,000 distinct candidate name/type queries. A and AAAA both count. This preserves candidate headroom when ordinary brute force adds IPv6. Ordinary root/child batches have at most 1,000 labels and query A/AAAA concurrently; at most two massdns processes run across the scan. DNSGen and empty-parent work also query both types in parallel.

DNSGen starts one batch on the first observed subdomain and every 25 newly retained seeds. Its 180-second limit counts active work, including waiting for DNS capacity, rather than idle gaps. Empty-parent exploration similarly runs on arriving events, retains its 60-second active budget and leaves classification slots for later known ancestors by limiting the initial ranked survey to 25 parents.

The query allocator holds up to 40,000 queries for enabled DNSGen and 4,000 for enabled empty-parent discovery; each reservation is clamped to one quarter of a smaller custom total. Static brute force defers at most 100 eligible parents when those reservations block it, then resumes after the priority modules finish/release unused capacity. Errored or absent modules cannot hold the allocator forever. Scope/depth eligibility is checked before retaining a deferred parent. Full-name/type query deduplication and unique name emission continue across resumption.

Resolver input defaults to the documented unfiltered Cloudflare and Google endpoints, without downloading a public resolver list. Each real scan validates its own network: exact A/AAAA controls, another stable A control, two random NXDOMAIN controls and median latency. Checks run concurrently under a 10-second overall limit. System DNS is a fallback only when no preferred endpoint passes; it must pass the same controls. No passing endpoint is an error, not a pretend empty scan. A custom resolver file/URL is bounded to 64 endpoints and validated identically. Build warmup prepares inputs but cannot cache another machine's validation result.

Massdns uses at most 50 outstanding lookups per validated endpoint per process (also bounded by `dns.brute_threads`), verifies reply-source IPs and makes three transport attempts instead of its default 50. Terminal failures are visible through NDJSON `Je`; excessive failures halve concurrency down to five, and at most 100 failed names per batch receive one additional bounded pass. Negative responses are not retried. Positive names are reconfirmed with a validated resolver, preferring another provider when available. Wrong owners, errors and timeouts cannot establish existence. A matching dangling CNAME remains valid name evidence even when its target is NXDOMAIN.

Logs include per-strategy distinct candidate queries, unique confirmed names and aggregate call seconds (parallel calls can overlap), plus resolver validation, positive confirmations/rejections, terminal failures, retries and current concurrency. Candidate limits exclude control and transport retry packets; all are still inside the elapsed runtime budget.

Primary sources: [MassDNS authenticity and options](https://github.com/blechschmidt/massdns), [Cloudflare endpoints](https://developers.cloudflare.com/1.1.1.1/infrastructure/network-operators/), [Google endpoints](https://developers.google.com/speed/public-dns/docs/using).

## Measured experiment (2026-10-14)

A native MassDNS binary queried a controlled loopback DNS server with 15 ms response delay. Each run checked 2,000 labels with A and AAAA (4,000 distinct queries), had exactly 200 known existing names, and included resolver validation, random canaries and positive reconfirmation. Three repetitions per configuration all recovered the exact 200-name ground truth with no false positives observed.

| Processes | Lookup slots per resolver/process | Median seconds |
| ---: | ---: | ---: |
| 1 | 10 | 7.011 |
| 2 | 10 | 3.575 |
| 1 | 25 | 2.970 |
| 2 | 25 | 1.520 |
| 1 | 50 | 1.479 |
| 2 | 50 | 0.832 |

The selected 2×50 configuration was about 3.6 times faster than 1×25 in this experiment; this is not a production throughput or coverage guarantee. Live DNS-only controls from the development network passed for all four public endpoints with median latencies of 17–26 ms. Production scans measure their own endpoints instead of assuming that ranking applies everywhere.

Reproduce with development dependencies and a compiled massdns binary:

```sh
python -m bbot.test.benchmarks.dns_throughput --binary /path/to/massdns --output /tmp/dns-benchmark.json
BBOT_TEST_MASSDNS=/path/to/massdns python -m pytest bbot/test/test_step_1/test_dns_throughput.py -q
```

The experiment uses only loopback DNS traffic; it does not enumerate a customer domain.
