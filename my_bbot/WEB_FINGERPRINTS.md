# Initial web fingerprints

The shared `all-but-intense-http.yml` preset enables `whatweb` and `retirejs` for Naxus and GuardianSentry. Both retain the existing `HTTP_RESPONSE`, `TECHNOLOGY` and `FINDING` event types.

## Response metadata

`whatweb` intercepts in-scope responses before output. It runs WhatWeb v0.6.4 against saved HTTP headers and HTML at aggression 1, with redirect following disabled. It fingerprints at most three HTML responses per origin. Native httpx technology signatures are normalized on every response; aliases and matching version observations are combined. A signature is an observation, not a verified backend version.

```json
{
  "technologies": [
    {"name": "WordPress", "version": "6.6.2", "evidence": "WhatWeb response signature; httpx technology signature"}
  ],
  "favicon": {
    "url": "https://example.com/favicon.ico",
    "sha256": "<64 hexadecimal characters>",
    "mmh3": -12345
  },
  "access_challenge": {
    "provider": "Cloudflare",
    "action": "challenge",
    "evidence": "cf-mitigated: challenge"
  }
}
```

Optional fields are omitted when unavailable. Technology names, versions and evidence are limited to 100 characters. `TECHNOLOGY` retains its existing `technology` name field and additionally preserves `version` and `evidence`.

Favicons use up to two same-origin advertised/fallback URLs, once per origin; no redirects are followed. Only recognized image signatures up to 256 KiB are hashed. SHA-256 covers original bytes; signed MurmurHash3 covers MIME base64 (including line breaks), matching the common Shodan favicon convention. These are fingerprints, not product identification by themselves. A failed fetch or HTML response produces no fingerprint. Images are not executed or rendered.

## Challenge detection

No model or extra probe is needed. Detection uses the response already collected:

- Cloudflare: exactly one `cf-mitigated: challenge` header value.
- AWS WAF: `x-amzn-waf-action: challenge` with HTTP 202, or `captcha` with HTTP 405.

Other responses receive no `access_challenge` field. A 403, Cloudflare server header, page title or embedded CAPTCHA widget does not establish an access challenge. Missing markers leave the result unknown. The observation applies to this URL and scan context; it does not assert that every visitor needs a challenge, and headers can be imitated. This deliberately does not classify ordinary responses or attempt challenge bypass.

Provider references: [Cloudflare Challenge Pages](https://developers.cloudflare.com/cloudflare-challenges/challenge-types/challenge-pages/detect-response/), [AWS WAF action behavior](https://docs.aws.amazon.com/waf/latest/developerguide/waf-captcha-and-challenge-actions.html).

## Vulnerable JavaScript libraries

RetireJS scans discovered, in-scope `.js` URLs without following redirects. The preset includes low and higher severities. Each existing `FINDING` includes `component`, `version`, `cves`, `javascript_url`, associated page `url`, description, severity, and advisory URLs when supplied. Some advisories have no CVE. Matching an advisory is not proof of application exploitability. Undiscovered, bundled/obfuscated, inline and out-of-scope scripts are not guaranteed coverage.

## Consumer requirements

- Naxus installs the selected remote BBOT revision and downloads the preset from that same revision. Updating only its fallback preset does not change the deployed image. New metadata is kept in large-event previews as well as the full S3 record.
- GuardianSentry builds its pinned `bbot-guardian` submodule. Update the pin together with its URL metadata migration/ingester changes. GuardianSentryClient receives these fields through existing graph metadata.
- BBOT's dependency installer supplies Ruby/WhatWeb and architecture-selected Node/RetireJS during image warmup. Existing image build verification must succeed before promotion. The new source alone does not update a running image or database.

Focused tests are in `test_web_fingerprints.py` and `test_module_whatweb.py`. Set `BBOT_TEST_WHATWEB_BINARY`, `BBOT_TEST_RETIRE_BINARY` and `BBOT_TEST_RETIRE_REPOSITORY` to additionally exercise actual tool binaries and the RetireJS advisory feed.
