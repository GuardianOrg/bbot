# Bounded DNS depth discovery

`dnsdepth` distinguishes authoritative NOERROR/NODATA from NXDOMAIN and errors
using A and AAAA queries. It keeps target seeds independently of unresolved
event emission. Known names and their in-scope ancestors are classified first;
a survey of at most 25 ranked labels beneath apex targets follows, leaving
probe slots for later observed ancestors. Exploration starts as events arrive. Only parents with
NOERROR and no answer for both address types qualify. Their children are tested
with A and AAAA and emitted once.

Defaults per scan: 100 distinct parent probes, 20 empty parents, 100 ranked labels
per parent and a total 60-second active-work budget; idle time does not consume it. The shared brute-force budget remains
400,000 distinct name/type queries and 7,200 seconds across all modules/rounds.
Limits bound discovery rather than promise exhaustive coverage.

`baddns_zone` independently checks NS/SOA answers and authority sections to find
actual in-scope zone owners, then runs BadDNS AXFR/NSEC for each new zone. Target
seeds and retained empty parents are checked even without address records.
Defaults: 100 parent checks, 20 zones, 5,000 emitted names and 120 total seconds.
Cancellation also cancels child BadDNS tasks.

Wildcard discovery compares CNAME/TXT/MX/HTTPS/SVCB/NS with three random controls.
A record type is usable only when all controls succeed and agree. Candidate
evidence must differ and repeat consistently; IP differences alone do not pass.
Limits: 100 candidates per parent, 20 parents, 50 accepted names and 60 seconds
shared across wildcard work. Confirmed names retain their original DNS owner.

HTTPS, SVCB, NAPTR and DNAME are queried during ordinary DNS enrichment. Targets
are extracted without web requests and full RDATA is emitted as RAW_DNS_RECORD.
HTTPS/SVCB address hints are not treated as proven host-to-IP bindings.
