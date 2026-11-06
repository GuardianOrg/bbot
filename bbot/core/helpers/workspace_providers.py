"""Recognise hosted email and identity providers from a domain's MX and TXT records."""

import re

EMAIL_SERVICE = "email"
IDENTITY_SERVICE = "identity"

SIGNAL_MX = "mx"
SIGNAL_SPF = "spf"
SIGNAL_VERIFICATION_TXT = "verification-txt"

# provider id -> display name, MX host suffixes, SPF include suffixes, verification TXT prefixes.
# Only records the provider itself asks a domain owner to publish are signals: an SPF include
# means the provider sends mail for the domain, an MX means it receives it, and a verification
# TXT means the domain was added to an account with that provider.
WORKSPACE_PROVIDERS = {
    "google_workspace": {
        "name": "Google Workspace",
        "mx_suffixes": ("smtp.google.com", "aspmx.l.google.com", ".google.com", ".googlemail.com"),
        "spf_includes": ("_spf.google.com",),
        "txt_prefixes": (),
    },
    "microsoft_365": {
        "name": "Microsoft 365",
        "mx_suffixes": (".mail.protection.outlook.com", ".mx.microsoft"),
        "spf_includes": ("spf.protection.outlook.com",),
        "txt_prefixes": ("ms=ms",),
    },
    "amazon_workmail": {
        # inbound-smtp.<region>.amazonaws.com receives mail for both WorkMail and SES receipt rules
        "name": "Amazon WorkMail / SES",
        "mx_patterns": (re.compile(r"^inbound-smtp\.[a-z0-9-]+\.amazonaws\.com$"),),
        "spf_includes": (),
        "txt_prefixes": (),
    },
    "zoho_mail": {
        "name": "Zoho Mail",
        "mx_patterns": (re.compile(r"^mx[0-9]*\.zoho(mail)?\.[a-z.]+$"),),
        "spf_includes": ("zoho.com", "zoho.eu", "zoho.in", "zoho.com.au", "zoho.jp", "zohomail.com"),
        "txt_prefixes": ("zoho-verification=",),
    },
    "proton_mail": {
        "name": "Proton Mail",
        "mx_suffixes": ("mail.protonmail.ch", "mailsec.protonmail.ch"),
        "spf_includes": ("_spf.protonmail.ch",),
        "txt_prefixes": ("protonmail-verification=",),
    },
    "fastmail": {
        "name": "Fastmail",
        "mx_suffixes": (".messagingengine.com",),
        "spf_includes": ("spf.messagingengine.com",),
        "txt_prefixes": (),
    },
}

_spf_include_regex = re.compile(r"(?:^|\s)[+~?-]?include:([^\s]+)", re.I)


def mx_hostname(answer):
    """Exchange host of an MX answer such as '10 aspmx.l.google.com.'."""
    parts = str(answer or "").strip().split()
    return parts[-1].rstrip(".").lower() if parts else ""


def spf_includes(txt_value):
    value = str(txt_value or "").strip().lower()
    if not value.startswith("v=spf1"):
        return []
    return [match.rstrip(".") for match in _spf_include_regex.findall(value)]


def _host_matches(host, suffixes):
    return any(host == suffix.lstrip(".") or host.endswith(suffix if suffix.startswith(".") else f".{suffix}")
               for suffix in suffixes)


def detect_workspace_providers(mx_answers, txt_values):
    """{provider id: sorted signals} for every provider the MX answers and TXT values point at."""
    mx_hosts = [host for host in (mx_hostname(answer) for answer in mx_answers) if host]
    txt_values = [str(value or "").strip().lower() for value in txt_values]
    includes = [include for value in txt_values for include in spf_includes(value)]
    detected = {}
    for provider, rule in WORKSPACE_PROVIDERS.items():
        signals = set()
        if any(_host_matches(host, rule.get("mx_suffixes", ())) for host in mx_hosts):
            signals.add(SIGNAL_MX)
        if any(pattern.match(host) for host in mx_hosts for pattern in rule.get("mx_patterns", ())):
            signals.add(SIGNAL_MX)
        if any(_host_matches(include, rule["spf_includes"]) for include in includes):
            signals.add(SIGNAL_SPF)
        if any(value.startswith(prefix) for value in txt_values for prefix in rule["txt_prefixes"]):
            signals.add(SIGNAL_VERIFICATION_TXT)
        if signals:
            detected[provider] = sorted(signals)
    return detected
