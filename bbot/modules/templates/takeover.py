import re


_AWS_ELB_CNAME = re.compile(
    r"^[a-z0-9-]+(?:\.[a-z0-9-]+)?\.elb(?:\.[a-z0-9-]+)?\.amazonaws\.com$"
)


def is_aws_elb_cname(target):
    """AWS assigns ELB DNS names; a stale one is not a claimable provider hostname."""
    return bool(_AWS_ELB_CNAME.fullmatch(str(target).strip().rstrip(".").lower()))


def takeover_finding_title(host, provider):
    """Use the same finding identity for a provider on a host across takeover scanners."""
    normalized_host = str(host).strip().rstrip(".").lower()
    normalized_provider = str(provider).strip().lower()
    return f"Potential subdomain takeover via {normalized_provider} on {normalized_host}"
