from types import SimpleNamespace

import pytest

from my_bbot.modules.offchain_scope_filter import offchain_scope_filter


def make_event(event_type, data=None, host=None, resolved_hosts=None, dns_children=None, tags=None, parent=None):
    event = SimpleNamespace(
        type=event_type,
        data=data,
        host=host,
        resolved_hosts=resolved_hosts or [],
        dns_children=dns_children,
        tags=tags or [],
        parent=parent,
    )

    def get_parents(include_self=False):
        parents = [event] if include_self else []
        parent_event = event.parent
        while parent_event is not None and not isinstance(parent_event, str):
            parents.append(parent_event)
            parent_event = getattr(parent_event, "parent", None)
        return parents

    event.get_parents = get_parents
    return event


async def create_scope_filter(scope_targets, seed_events=None):
    seed_events = seed_events if seed_events is not None else [
        SimpleNamespace(type="DNS_NAME", data="example.com", input="example.com"),
    ]
    scan = SimpleNamespace(
        config={"modules": {"offchain_scope_filter": {"scope_targets": scope_targets}}, "web": {}},
        web_config={},
        helpers=None,
        target=SimpleNamespace(seeds=SimpleNamespace(event_seeds=seed_events)),
    )
    module = offchain_scope_filter(scan)
    module._name = "offchain_scope_filter"
    assert await module.setup() is True
    return module


@pytest.mark.asyncio
async def test_offchain_scope_filter_limits_domains_and_repositories_to_world_scope():
    module = await create_scope_filter([
        "domain:example.com",
        "code_repository_owner:https://github.com/acme",
    ])

    allowed_domain = make_event("DNS_NAME", data="api.example.com", host="api.example.com")
    blocked_domain = make_event("DNS_NAME", data="vendor.net", host="vendor.net")
    allowed_repo = make_event(
        "CODE_REPOSITORY",
        data={"url": "https://github.com/acme/api"},
        host="github.com",
    )
    blocked_repo = make_event(
        "CODE_REPOSITORY",
        data={"url": "https://github.com/not-acme/api"},
        host="github.com",
    )

    assert await module.handle_event(allowed_domain) is True
    assert await module.handle_event(allowed_repo) is True

    blocked_domain_result = await module.handle_event(blocked_domain)
    blocked_repo_result = await module.handle_event(blocked_repo)

    assert blocked_domain_result == (False, "dns event is outside the seeded domain scope")
    assert blocked_repo_result == (False, "repository is outside the seeded repository scope")


@pytest.mark.asyncio
async def test_offchain_scope_filter_email_seed_does_not_authorize_domain_scope():
    module = await create_scope_filter(["email:security@example.com"], seed_events=[])

    exact_email = make_event("EMAIL_ADDRESS", data="security@example.com")
    sibling_email = make_event("EMAIL_ADDRESS", data="admin@example.com")
    domain_event = make_event("DNS_NAME", data="example.com", host="example.com")

    assert await module.handle_event(exact_email) is True
    assert await module.handle_event(sibling_email) == (
        False,
        "email address is outside the seeded email or domain scope",
    )
    assert await module.handle_event(domain_event) == (
        False,
        "dns event is outside the seeded domain scope",
    )


@pytest.mark.asyncio
async def test_offchain_scope_filter_allows_emails_discovered_from_seeded_domains():
    module = await create_scope_filter(["domain:example.com"])

    allowed_email = make_event("EMAIL_ADDRESS", data="security@mail.example.com")
    blocked_email = make_event("EMAIL_ADDRESS", data="security@vendor.net")

    assert await module.handle_event(allowed_email) is True
    assert await module.handle_event(blocked_email) == (
        False,
        "email address is outside the seeded email or domain scope",
    )


@pytest.mark.asyncio
async def test_offchain_scope_filter_exact_repository_seed_does_not_authorize_owner():
    module = await create_scope_filter([
        "code_repository:https://github.com/acme/api",
        "code_repository:https://gitlab.com/acme/security/tools/scanner",
    ])

    allowed_repo = make_event(
        "CODE_REPOSITORY",
        data={"url": "https://github.com/acme/api"},
        host="github.com",
    )
    allowed_gitlab_subgroup_repo = make_event(
        "CODE_REPOSITORY",
        data={"url": "https://gitlab.com/acme/security/tools/scanner"},
        host="gitlab.com",
    )
    blocked_sibling_repo = make_event(
        "CODE_REPOSITORY",
        data={"url": "https://github.com/acme/other"},
        host="github.com",
    )
    blocked_gitlab_sibling_repo = make_event(
        "CODE_REPOSITORY",
        data={"url": "https://gitlab.com/acme/security/tools/other"},
        host="gitlab.com",
    )

    assert await module.handle_event(allowed_repo) is True
    assert await module.handle_event(allowed_gitlab_subgroup_repo) is True

    blocked_result = await module.handle_event(blocked_sibling_repo)
    blocked_gitlab_result = await module.handle_event(blocked_gitlab_sibling_repo)

    assert blocked_result == (False, "repository is outside the seeded repository scope")
    assert blocked_gitlab_result == (False, "repository is outside the seeded repository scope")


@pytest.mark.asyncio
async def test_offchain_scope_filter_only_allows_ips_from_a_and_aaaa_resolution():
    module = await create_scope_filter(["domain:example.com"])

    allowed_a_record = make_event(
        "RAW_DNS_RECORD",
        data={"host": "api.example.com", "type": "A", "answer": "1.1.1.1"},
        host="api.example.com",
    )
    allowed_domain = make_event(
        "DNS_NAME",
        data="api.example.com",
        host="api.example.com",
        resolved_hosts=["2.2.2.2"],
        dns_children={"A": ["2.2.2.2"]},
    )
    allowed_ip_from_domain = make_event("IP_ADDRESS", data="2.2.2.2", host="2.2.2.2", parent=allowed_domain)
    allowed_port_from_domain_ip = make_event("OPEN_TCP_PORT", data="2.2.2.2:443", host="2.2.2.2")
    blocked_domain_port_with_resolved_hosts = make_event(
        "OPEN_TCP_PORT",
        data="api.example.com:443",
        host="api.example.com",
        resolved_hosts=["2.2.2.2"],
    )
    blocked_mx_record = make_event(
        "RAW_DNS_RECORD",
        data={"host": "api.example.com", "type": "MX", "answer": "9.9.9.9"},
        host="api.example.com",
    )
    domain_tied_geolocation = make_event(
        "GEOLOCATION",
        data={"host": "api.example.com", "ip": "8.8.8.8"},
        host="api.example.com",
    )
    allowed_geolocation = make_event("GEOLOCATION", data={"ip": "1.1.1.1"}, host="1.1.1.1")
    blocked_geolocation = make_event("GEOLOCATION", data={"ip": "9.9.9.9"}, host="9.9.9.9")
    blocked_domain_tied_geolocation = make_event("GEOLOCATION", data={"ip": "8.8.8.8"}, host="8.8.8.8")

    assert await module.handle_event(allowed_a_record) is True
    assert await module.handle_event(allowed_domain) is True
    assert await module.handle_event(allowed_ip_from_domain) is True
    assert await module.handle_event(allowed_port_from_domain_ip) is True
    assert await module.handle_event(blocked_domain_port_with_resolved_hosts) == (
        False,
        "port/protocol event is not keyed to an allowed IP address",
    )
    assert await module.handle_event(blocked_mx_record) is True
    assert await module.handle_event(allowed_geolocation) is True

    domain_tied_result = await module.handle_event(domain_tied_geolocation)
    blocked_geolocation_result = await module.handle_event(blocked_geolocation)
    blocked_domain_tied_result = await module.handle_event(blocked_domain_tied_geolocation)

    assert domain_tied_result == (
        False,
        "IP analysis event is not tied to an allowed IP from seeded domain A/AAAA data",
    )
    assert blocked_geolocation_result == (
        False,
        "IP analysis event is not tied to an allowed IP from seeded domain A/AAAA data",
    )
    assert blocked_domain_tied_result == (
        False,
        "IP analysis event is not tied to an allowed IP from seeded domain A/AAAA data",
    )


@pytest.mark.asyncio
async def test_offchain_scope_filter_allows_open_ports_by_netloc_for_seeded_ips():
    module = await create_scope_filter(["ip_address:10.0.0.2"])

    allowed_tcp_port = make_event("OPEN_TCP_PORT", data="10.0.0.2:443")
    allowed_udp_port = make_event("OPEN_UDP_PORT", data="10.0.0.2:123")
    allowed_protocol = make_event("PROTOCOL", data={"host": "10.0.0.2", "port": 443, "transport": "tcp"})
    blocked_tcp_port = make_event("OPEN_TCP_PORT", data="10.0.0.3:443")

    assert await module.handle_event(allowed_tcp_port) is True
    assert await module.handle_event(allowed_udp_port) is True
    assert await module.handle_event(allowed_protocol) is True
    assert await module.handle_event(blocked_tcp_port) == (
        False,
        "port/protocol event is not keyed to an allowed IP address",
    )


@pytest.mark.asyncio
async def test_offchain_scope_filter_allows_urls_for_scoped_domains_and_ip_ranges():
    module = await create_scope_filter([
        "domain:example.com",
        "ip_range:10.0.0.0/30",
    ])

    allowed_domain_url = make_event("URL", data="https://portal.example.com/login", host="portal.example.com")
    allowed_ip_url = make_event("URL", data="https://10.0.0.2/login", host="10.0.0.2")
    blocked_domain_url = make_event("URL", data="https://vendor.net/login", host="vendor.net")
    blocked_ip_url = make_event("URL", data="https://8.8.8.8/login", host="8.8.8.8")

    assert await module.handle_event(allowed_domain_url) is True
    assert await module.handle_event(allowed_ip_url) is True

    blocked_domain_result = await module.handle_event(blocked_domain_url)
    blocked_ip_result = await module.handle_event(blocked_ip_url)

    assert blocked_domain_result == (
        False,
        "web event is outside the seeded domain and IP scope",
    )
    assert blocked_ip_result == (
        False,
        "web event is outside the seeded domain and IP scope",
    )


@pytest.mark.asyncio
async def test_offchain_scope_filter_keeps_ip_range_events_to_seeded_ranges():
    module = await create_scope_filter(["ip_range:10.0.0.0/30"])

    allowed_range = make_event("IP_RANGE", data="10.0.0.0/30", host="10.0.0.0/30")
    blocked_range = make_event("IP_RANGE", data="10.0.0.0/24", host="10.0.0.0/24")

    assert await module.handle_event(allowed_range) is True
    assert await module.handle_event(blocked_range) == (
        False,
        "IP range event is outside the seeded IP range scope",
    )
