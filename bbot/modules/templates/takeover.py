def takeover_finding_title(host, provider):
    """Use the same finding identity for a provider on a host across takeover scanners."""
    normalized_host = str(host).strip().rstrip(".").lower()
    normalized_provider = str(provider).strip().lower()
    return f"Potential subdomain takeover via {normalized_provider} on {normalized_host}"
