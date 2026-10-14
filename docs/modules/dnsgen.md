# DNSGen discovery

`dnsgen` uses the published DNSGen 1.0.4 static permutation engine. It inserts words
at DNS label boundaries, prepends/appends words with and without hyphens, replaces
known substrings and changes numeric sequences by up to three while retaining
zero padding. An additional exact label/hyphen-token rule covers short words that
DNSGen excludes, such as `dev`, `api`, `eu` and `us`. No LLM is involved.

The module operates on full names, preserving the public suffix (`example.co.uk`)
and checking every candidate against scan scope. It retains in-scope unresolved
names when the scan emits them. Rule output is consumed round-robin so insertion
does not monopolize the candidate budget. Words come from a bounded common list
and observed names within the same registrable domain; concurrent scanners do
not share DNSGen's mutable word state.

Generation runs at scan finish. Newly discovered names may seed the next finish
round. Limits apply across all rounds and must be finite and positive:

| Setting | Default |
| --- | ---: |
| Distinct candidate names per scan | 50,000 |
| Candidates per registrable domain | 10,000 |
| Candidates per observed name | 300 |
| Retained seed names | 5,000 |
| Words per domain | 64 |
| Finish rounds | 2 |
| DNS batch size | 1,000 |
| Total generation/DNS runtime budget | 180 seconds |

A and AAAA are queried separately, including IPv6-only results. Confirmed names
are emitted once. Observed names and previously generated names are excluded.
The shared DNS brute helper deduplicates exact `(full hostname, record type)`
queries across modules, parents and rounds. `dns.brute_max_candidates` defaults
to 200,000 across the scan; it counts A/AAAA separately and excludes random
wildcard-control probes and normal DNS event enrichment. Attempted queries remain
claimed after a failure/cancellation, preventing repeated permutation attempts.

The runtime deadline starts at the first finish round and persists through later
rounds. Massdns receives the remaining time as its subprocess timeout as well.
Budget exhaustion ends this discovery step and is logged; it does not mean all
possible names were tested. No unlimited-budget mode is available.

`my_bbot/all-but-intense-http.yml` enables this module instead of the older
`dnsbrute_mutations` expansion, keeps the small static `dnsbrute` list, and enables
`baddns_zone` for AXFR/NSEC discoveries. CertSpotter follows issuance pagination.
GuardianSentry builds its sidecar from the pinned `bbot-guardian` submodule and
uses this preset by default, so changing its submodule revision carries both
the code and the configured limits into the next image build.
