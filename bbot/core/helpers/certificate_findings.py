"""Initial TLS facts that are actionable without observing a later change."""
from datetime import datetime, timezone
from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit

TRACKING_ROOTS = ("sendgrid.net", "mailgun.net", "mailgun.org")
DAY_SECONDS = 86400


def _date(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _name(value):
    return str(value or "").strip().lower().rstrip(".")


def _covers(name, host):
    return name == host or (name.startswith("*.") and host.endswith(name[1:]) and len(host.split(".")) == len(name.split(".")))


def initial_certificate_findings(data, *, now=None, explicit_ip=False):
    """Report verified leaf problems; never treat a discovered IP's default leaf as its domain's certificate."""
    host = _name(data.get("host"))
    if not host:
        return []
    try:
        ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if is_ip and not explicit_ip:
        return []
    url = urlsplit(data.get("url") or f"https://{'[' + host + ']' if ':' in host else host}:{data.get('port') or 443}/")
    if url.scheme != "https" or not url.hostname:
        return []
    netloc = f"[{url.hostname}]" if ":" in url.hostname else url.hostname.lower()
    if url.port and url.port != 443:
        netloc += f":{url.port}"
    endpoint = urlunsplit(("https", netloc, "/", "", ""))
    now = now or datetime.now(timezone.utc)
    certificate = data.get("certificate") or {}
    expires = _date(data.get("certNotAfter"))
    begins = _date(certificate.get("notBefore"))
    window_days = 30
    if begins and expires and 0 < (expires - begins).total_seconds() <= 100 * DAY_SECONDS:
        window_days = min(10, (expires - begins).total_seconds() / DAY_SECONDS / 6)
    expired = data.get("certIsExpired") is True or (expires is not None and expires <= now)
    problems = []
    if expired:
        problems.append(("expired", "MEDIUM", f"TLS certificate is expired for {host}", "Renew the certificate and deploy the renewed chain on every serving endpoint."))
    elif expires and (expires - now).total_seconds() <= window_days * DAY_SECONDS:
        problems.append(("expiring", "LOW", f"TLS certificate expires soon for {host}", "Verify automated renewal and deploy the renewed certificate before expiry."))
    sans = [_name(value) for value in data.get("certSanDomains") or [] if _name(value)]
    common_name = _name(data.get("certSubjectCn"))
    names = sans or ([common_name] if common_name else [])
    covers = is_ip or any(_covers(name, host) for name in names) or (not names and "subject" not in certificate)
    identities = sans + ([common_name] if common_name else [])
    tracking = bool(identities) and all(any(name.removeprefix("*.") == root or name.removeprefix("*.").endswith("." + root) for root in TRACKING_ROOTS) for name in identities)
    error = str(data.get("certValidationError") or "")
    expiry_error = "expir" in error.lower()
    if (covers or tracking) and data.get("certChainTrusted") is False and not (expired and expiry_error):
        problems.append(("chain", "MEDIUM", f"TLS certificate chain is not trusted for {host}", "Deploy a publicly trusted certificate with the full intermediate chain and verify it externally."))
    if not covers and not tracking:
        problems.append(("hostname", "MEDIUM", f"TLS certificate does not cover hostname {host}", "Deploy a certificate whose SAN list covers this hostname."))
    evidence = {key: data[key] for key in ("certNotAfter", "certFingerprintSha256", "certSanDomains", "certSubjectCn", "certIssuerCn", "certChainTrusted", "certValidationError") if key in data}
    return [{"host": host, "url": endpoint, "severity": severity, "title": title, "category": "TLS Certificate",
             "dedupe_key": f"tls-initial:{kind}:{endpoint}", "evidence": evidence,
             "description": f"{title}. The initial TLS handshake at {endpoint} returned the recorded certificate and validation result. Clients that verify TLS identity, trust and expiry may reject this connection. Confirm that this is the intended public endpoint and inspect the recorded leaf certificate and chain. This is an initial scan observation, not evidence of a later certificate change.",
             "recommendation": recommendation}
            for kind, severity, title, recommendation in problems]
