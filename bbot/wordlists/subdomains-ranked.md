# Bundled bounded DNS wordlist

The first 5,000 distinct valid labels preserve SecLists top1million ordering.
The remaining 5,000 are previously unseen labels from n0kovo tiny, preserving
its frequency order. Every label is lowercased, validated and deduplicated.
This combination is shipped locally; scans do not download a DNS wordlist.

Sources fetched 2026-10-14:
- https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt (SecLists MIT)
- https://raw.githubusercontent.com/n0kovo/n0kovo_subdomains/main/n0kovo_subdomains_tiny.txt (GPL-3.0)

The ordering is source ranking, not a measured target-specific coverage score.
The empty-parent module uses the first 100 labels; ordinary nested brute force
uses the first 1,000. Root brute force uses 10,000. Depth defaults to five.
All share candidate deduplication and a maximum one-hour wall-clock budget.
