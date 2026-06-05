import asyncio
import ipaddress
import re
from contextlib import suppress

from bbot.errors import ValidationError
from bbot.core.helpers.dns.engine import all_rdtypes
from bbot.core.helpers.dns.helpers import extract_targets, service_record
from bbot.core.helpers.regexes import dns_name_extraction_regex, email_regex, url_regexes
from bbot.modules.base import BaseInterceptModule, BaseModule


_caa_regex = r"^(?P<flags>[0-9]+) +(?P<property>\w+) +\"(?P<text>[^;\"]*);* *(?P<extensions>[^\"]*)\"$"
caa_regex = re.compile(_caa_regex)

_bimi_regex = r"^v=(?P<v>BIMI1);\s?(?:l=(?P<l>https?://[^;\s]{1,255})?)?;?(?:\s?a=(?P<a>https://[^;\s]{1,255})?;?)?$"
bimi_regex = re.compile(_bimi_regex, re.I)

_dmarc_regex = r"^v=(?P<v>DMARC1); *(?P<kvps>.*)$"
dmarc_regex = re.compile(_dmarc_regex, re.I)

_dmarc_kvp_regex = r"(?P<k>\w+)\s*=\s*(?P<v>[^;]+);*"
dmarc_kvp_regex = re.compile(_dmarc_kvp_regex)

_tlsrpt_regex = r"^v=(?P<v>TLSRPTv[0-9]+); *(?P<kvps>.*)$"
tlsrpt_regex = re.compile(_tlsrpt_regex, re.I)

_tlsrpt_kvp_regex = r"(?P<k>\w+)=(?P<v>[^;]+);*"
tlsrpt_kvp_regex = re.compile(_tlsrpt_kvp_regex)

_csul = r"(?P<uri>[^, ]+)"
csul = re.compile(_csul)

simple_url_regex = re.compile(r"https?://[^;\s]+", re.I)


class DNSResolve(BaseInterceptModule):
    watched_events = ["*"]
    produced_events = ["DNS_NAME", "IP_ADDRESS", "RAW_DNS_RECORD", "EMAIL_ADDRESS", "URL_UNVERIFIED", "FINDING"]
    meta = {"description": "Perform DNS resolution", "created_date": "2022-04-08", "author": "@TheTechromancer"}
    _priority = 1
    scope_distance_modifier = None

    class HostModule(BaseModule):
        _name = "host"
        _type = "internal"

    @property
    def module_threads(self):
        return self.dns_config.get("threads", 25)

    async def setup(self):
        self.dns_config = self.scan.config.get("dns", {})
        self.dns_disable = self.dns_config.get("disable", False)
        if self.dns_disable:
            return None, "DNS resolution is disabled in the config"

        self.minimal = self.dns_config.get("minimal", False)
        self.emit_unresolved = self.dns_config.get("emit_unresolved", True)
        self.max_unresolved_subdomains_per_module = max(
            0, int(self.dns_config.get("max_unresolved_subdomains_per_module", 0) or 0)
        )
        self.minimal_rdtypes = ("A", "AAAA", "CNAME")
        if self.minimal:
            self.non_minimal_rdtypes = ()
        else:
            self.non_minimal_rdtypes = tuple([t for t in all_rdtypes if t not in self.minimal_rdtypes])
        self.dns_search_distance = max(0, int(self.dns_config.get("search_distance", 1)))
        self.emit_out_of_scope_children = self.dns_config.get("emit_out_of_scope_children", True)
        self._emit_raw_records = None
        self.bimi_selectors = [
            selector.strip()
            for selector in str(self.dns_config.get("bimi_selectors", "default,email,mail,bimi")).split(",")
            if selector.strip()
        ]

        self.host_module = self.HostModule(self.scan)
        self.children_emitted = set()
        self.children_emitted_raw = set()
        self.hosts_resolved = set()
        self.host_resolution_cache = {}
        self.unresolved_subdomains_by_module = {}
        self.pending_unresolved_subdomains_by_module = {}
        self.unresolved_subdomain_budget_condition = asyncio.Condition()
        self.unresolved_subdomains_module_warned = set()
        self.wildcard_events_seen = set()
        self.policy_queries_done = set()
        self.policy_events_emitted = set()

        return True

    async def filter_event(self, event):
        if (not event.host) or (event.type in ("IP_RANGE",)):
            return False, "event does not have host attribute"
        return True

    async def handle_event(self, event, **kwargs):
        event_is_ip = self.helpers.is_ip(event.host)
        if event_is_ip:
            minimal_rdtypes = ("PTR",)
            non_minimal_rdtypes = ()
        else:
            minimal_rdtypes = self.minimal_rdtypes
            non_minimal_rdtypes = self.non_minimal_rdtypes

        # first, we find or create the main DNS_NAME or IP_ADDRESS associated with this event
        main_host_event, whitelisted, blacklisted, new_event = self.get_dns_parent(event)
        host_cache_key = self._host_resolution_cache_key(event.host)
        queried_rdtypes = set()
        original_tags = set(event.tags)
        budget_module = None
        budget_host_key = None

        # minimal resolution - first, we resolve A/AAAA records for scope purposes
        if new_event or event is main_host_event:
            if self._unresolved_subdomain_budget_exceeded(main_host_event):
                budget_module = self._unresolved_subdomain_module(main_host_event) or main_host_event.module
                return False, f'unresolved subdomain budget exceeded for module "{budget_module}"'
            cached_resolution = self.host_resolution_cache.get(host_cache_key)
            if cached_resolution is not None:
                queried_rdtypes.update(cached_resolution.get("queried_rdtypes", set()))
                event_data_changed = self.apply_host_resolution_cache(main_host_event, cached_resolution)
                whitelisted, blacklisted = self.check_scope(main_host_event)
                if blacklisted:
                    return False, "it has a blacklisted DNS record"
                if cached_resolution.get("unresolved") and not self.emit_unresolved:
                    return False, "unresolved DNS events are disabled"
                if event_data_changed:
                    if self.is_duplicate_wildcard_event(event):
                        if not event._graph_important:
                            return (
                                False,
                                "it's a DNS wildcard, and its module already emitted a similar wildcard event",
                            )
                        else:
                            self.debug(
                                f"Event {event} was already emitted by its module, but it's graph-important so it gets a pass"
                            )
                    if event.type == "DNS_NAME" and self.scan.ingress_module.is_incoming_duplicate(event, add=True):
                        if not event._graph_important:
                            return (
                                False,
                                "it's a DNS wildcard, and its module already emitted a similar wildcard event",
                            )
                        else:
                            self.debug(
                                f"Event {event} was already emitted by its module, but it's graph-important so it gets a pass"
                            )
                needs_non_minimal = (
                    (not event_is_ip)
                    and main_host_event.scope_distance < self._dns_search_distance
                    and not set(non_minimal_rdtypes).issubset(queried_rdtypes)
                )
                if not needs_non_minimal:
                    event.scope_distance = main_host_event.scope_distance
                    event._resolved_hosts = main_host_event.resolved_hosts
                    return
            else:
                budget_allowed, budget_module, budget_host_key = await self._reserve_unresolved_subdomain_budget(
                    main_host_event
                )
                if not budget_allowed:
                    return False, f'unresolved subdomain budget exceeded for module "{budget_module}"'
                try:
                    await self.resolve_event(main_host_event, types=minimal_rdtypes)
                    queried_rdtypes.update(minimal_rdtypes)
                    # are any of its IPs whitelisted/blacklisted?
                    whitelisted, blacklisted = self.check_scope(main_host_event)
                    if whitelisted and event.scope_distance > 0:
                        self.debug(
                            f"Making {main_host_event} in-scope because it resolves to an in-scope resource (A/AAAA)"
                        )
                        main_host_event.scope_distance = 0
                except BaseException:
                    await self._release_unresolved_subdomain_budget(budget_module, budget_host_key)
                    raise

        # abort if the event resolves to something blacklisted
        if blacklisted:
            self.cache_host_resolution(host_cache_key, main_host_event, queried_rdtypes)
            await self._release_unresolved_subdomain_budget(budget_module, budget_host_key)
            return False, "it has a blacklisted DNS record"

        # DNS resolution for hosts that aren't IPs
        if not event_is_ip:
            # if the event is within our dns search distance, resolve the rest of our records
            if main_host_event.scope_distance < self._dns_search_distance:
                try:
                    non_minimal_rdtypes_to_resolve = tuple(
                        rdtype for rdtype in non_minimal_rdtypes if rdtype not in queried_rdtypes
                    )
                    await self.resolve_event(main_host_event, types=non_minimal_rdtypes_to_resolve)
                    queried_rdtypes.update(non_minimal_rdtypes_to_resolve)
                    if (new_event or event is main_host_event) and non_minimal_rdtypes_to_resolve:
                        await self.emit_policy_events(main_host_event)
                    # check for wildcards if the event is within the scan's search distance
                    if new_event and main_host_event.scope_distance <= self.scan.scope_search_distance:
                        event_data_changed = await self.handle_wildcard_event(main_host_event)
                        if event_data_changed:
                            if self.is_duplicate_wildcard_event(event):
                                if not event._graph_important:
                                    self.cache_host_resolution(host_cache_key, main_host_event, queried_rdtypes)
                                    await self._release_unresolved_subdomain_budget(budget_module, budget_host_key)
                                    return (
                                        False,
                                        "it's a DNS wildcard, and its module already emitted a similar wildcard event",
                                    )
                                else:
                                    self.debug(
                                        f"Event {event} was already emitted by its module, but it's graph-important so it gets a pass"
                                    )
                            # since data has changed, we check again whether it's a duplicate
                            if event.type == "DNS_NAME" and self.scan.ingress_module.is_incoming_duplicate(
                                event, add=True
                            ):
                                if not event._graph_important:
                                    self.cache_host_resolution(host_cache_key, main_host_event, queried_rdtypes)
                                    await self._release_unresolved_subdomain_budget(budget_module, budget_host_key)
                                    return (
                                        False,
                                        "it's a DNS wildcard, and its module already emitted a similar wildcard event",
                                    )
                                else:
                                    self.debug(
                                        f"Event {event} was already emitted by its module, but it's graph-important so it gets a pass"
                                    )
                except BaseException:
                    await self._release_unresolved_subdomain_budget(budget_module, budget_host_key)
                    raise

        # if there weren't any DNS children and it's not an IP address, tag as unresolved
        unresolved = False
        if not main_host_event.raw_dns_records and not event_is_ip:
            unresolved = True
            main_host_event.add_tag("unresolved")
            if self.emit_unresolved:
                main_host_event.type = "DNS_NAME_UNRESOLVED"

        self.cache_host_resolution(host_cache_key, main_host_event, queried_rdtypes, unresolved=unresolved)
        await self._release_unresolved_subdomain_budget(budget_module, budget_host_key, unresolved=unresolved)

        if unresolved and not self.emit_unresolved:
            return False, "unresolved DNS events are disabled"

        # main_host_event.add_tag(f"resolve-distance-{main_host_event.dns_resolve_distance}")

        dns_tags = main_host_event.tags.difference(original_tags)

        dns_resolve_distance = getattr(main_host_event, "dns_resolve_distance", 0)
        runaway_dns = dns_resolve_distance >= self.helpers.dns.runaway_limit
        if runaway_dns:
            # kill runaway DNS chains
            self.debug(
                f"Skipping DNS children for {event} because their DNS resolve distances would be greater than the configured value for this scan ({self.helpers.dns.runaway_limit})"
            )
            main_host_event.add_tag(f"runaway-dns-{dns_resolve_distance}")
        else:
            # emit dns children
            await self.emit_dns_children_raw(main_host_event, dns_tags)
            if not self.minimal:
                await self.emit_dns_children(main_host_event)

            # emit the main DNS_NAME or IP_ADDRESS
            if (
                new_event
                and event is not main_host_event
                and main_host_event.scope_distance <= self._dns_search_distance
            ):
                if self.is_duplicate_wildcard_event(main_host_event):
                    if main_host_event._graph_important:
                        await self.emit_event(main_host_event)
                    else:
                        self.debug(
                            f"Not queueing {main_host_event} because its wildcard DNS_NAME was already emitted"
                        )
                else:
                    await self.emit_event(main_host_event)

        # transfer scope distance to event
        event.scope_distance = main_host_event.scope_distance
        event._resolved_hosts = main_host_event.resolved_hosts

    def cache_host_resolution(self, host_cache_key, event, queried_rdtypes, unresolved=False):
        if not host_cache_key:
            return
        self.hosts_resolved.add(host_cache_key)
        self.host_resolution_cache[host_cache_key] = {
            "data": event.data,
            "type": event.type,
            "unresolved": bool(unresolved),
            "scope_distance": event.scope_distance,
            "tags": set(event.tags),
            "resolved_hosts": set(event.resolved_hosts),
            "raw_dns_records": self.copy_dns_map(event.raw_dns_records),
            "dns_children": self.copy_dns_map(event.dns_children),
            "queried_rdtypes": set(queried_rdtypes),
        }

    def apply_host_resolution_cache(self, event, cached_resolution):
        original_data = event.data
        cached_data = cached_resolution.get("data")
        if cached_data and "target" not in event.tags:
            event.data = cached_data
        cached_type = cached_resolution.get("type")
        if cached_resolution.get("unresolved") and self.emit_unresolved:
            event.type = "DNS_NAME_UNRESOLVED"
        cached_scope_distance = cached_resolution.get("scope_distance")
        if isinstance(cached_scope_distance, int):
            event.scope_distance = min(event.scope_distance, cached_scope_distance)
        for tag in cached_resolution.get("tags", set()):
            if tag == "target" and "target" not in event.tags:
                continue
            event.add_tag(tag)
        event._resolved_hosts = set(cached_resolution.get("resolved_hosts", set()))
        event.raw_dns_records = self.copy_dns_map(cached_resolution.get("raw_dns_records", {}))
        event.dns_children = self.copy_dns_map(cached_resolution.get("dns_children", {}))
        return event.data != original_data

    def _is_target_seed_event(self, event):
        return "target" in event.tags and getattr(event, "parent", None) is self.scan.root_event

    def _unresolved_subdomain_module(self, event):
        if (
            not self.max_unresolved_subdomains_per_module
            or self._is_target_seed_event(event)
            or event.type != "DNS_NAME"
            or self.helpers.is_ip(event.host)
        ):
            return None
        module = getattr(event, "module", None)
        if str(getattr(module, "name", module) or "") == self.host_module.name:
            module = getattr(getattr(event, "parent", None), "module", module)
        module_name = str(getattr(module, "name", module) or "")
        if not module_name:
            return None
        return module_name

    def _unresolved_subdomain_budget_exceeded(self, event):
        module_name = self._unresolved_subdomain_module(event)
        if not module_name:
            return False
        unresolved = self.unresolved_subdomains_by_module.get(module_name, set())
        if len(unresolved) < self.max_unresolved_subdomains_per_module:
            return False
        if module_name not in self.unresolved_subdomains_module_warned:
            self.unresolved_subdomains_module_warned.add(module_name)
            self.warning(
                f'Skipping further subdomain DNS resolution for "{module_name}" after '
                f"{len(unresolved):,} unresolved subdomains"
            )
        return True

    async def _reserve_unresolved_subdomain_budget(self, event):
        module_name = self._unresolved_subdomain_module(event)
        if not module_name:
            return True, None, None
        host_key = self._host_resolution_cache_key(event.host)
        async with self.unresolved_subdomain_budget_condition:
            while True:
                unresolved = self.unresolved_subdomains_by_module.setdefault(module_name, set())
                if len(unresolved) >= self.max_unresolved_subdomains_per_module or host_key in unresolved:
                    if module_name not in self.unresolved_subdomains_module_warned:
                        self.unresolved_subdomains_module_warned.add(module_name)
                        self.warning(
                            f'Skipping further subdomain DNS resolution for "{module_name}" after '
                            f"{len(unresolved):,} unresolved subdomains"
                        )
                    return False, module_name, host_key
                pending = self.pending_unresolved_subdomains_by_module.setdefault(module_name, set())
                if len(unresolved) + len(pending) < self.max_unresolved_subdomains_per_module:
                    pending.add(host_key)
                    return True, module_name, host_key
                await self.unresolved_subdomain_budget_condition.wait()

    async def _release_unresolved_subdomain_budget(self, module_name, host_key, unresolved=False):
        if not module_name or not host_key:
            return
        async with self.unresolved_subdomain_budget_condition:
            pending = self.pending_unresolved_subdomains_by_module.get(module_name)
            if pending is not None:
                pending.discard(host_key)
            if unresolved:
                self.unresolved_subdomains_by_module.setdefault(module_name, set()).add(host_key)
            self.unresolved_subdomain_budget_condition.notify_all()

    def copy_dns_map(self, dns_map):
        return {rdtype: set(values) for rdtype, values in dns_map.items()}

    def _host_resolution_cache_key(self, host):
        return str(host or "").strip().rstrip(".").lower()

    def is_duplicate_wildcard_event(self, event):
        if event.type != "DNS_NAME":
            return False
        if "_wildcard" not in str(event.data).split("."):
            return False
        wildcard_key = self._host_resolution_cache_key(event.data)
        if wildcard_key in self.wildcard_events_seen:
            return True
        self.wildcard_events_seen.add(wildcard_key)
        return False

    async def handle_wildcard_event(self, event):
        rdtypes = tuple(event.raw_dns_records)
        wildcard_rdtypes = await self.helpers.is_wildcard(
            event.host, rdtypes=rdtypes, raw_dns_records=event.raw_dns_records
        )
        for rdtype, (is_wildcard, wildcard_host) in wildcard_rdtypes.items():
            if is_wildcard is False:
                continue
            elif is_wildcard is True:
                event.add_tag("wildcard")
                wildcard_tag = "wildcard"
            else:
                event.add_tag(f"wildcard-{is_wildcard}")
                wildcard_tag = f"wildcard-{is_wildcard}"
            event.add_tag(f"{rdtype}-{wildcard_tag}")

        # wildcard event modification (www.evilcorp.com --> _wildcard.evilcorp.com)
        if wildcard_rdtypes:
            # these are the rdtypes that have wildcards
            wildcard_rdtypes_set = set(wildcard_rdtypes)
            # consider the event a full wildcard if all its records are wildcards
            event_is_wildcard = False
            if wildcard_rdtypes_set:
                event_is_wildcard = all(r[0] is True for r in wildcard_rdtypes.values())

            if event_is_wildcard:
                event.add_tag("wildcard-child")
                if event.type in ("DNS_NAME",) and "_wildcard" not in event.data.split("."):
                    wildcard_parent = self.helpers.parent_domain(event.host)
                    for rdtype, (_is_wildcard, _parent_domain) in wildcard_rdtypes.items():
                        if _is_wildcard:
                            wildcard_parent = _parent_domain
                            break
                    event.add_tag(f"wildcard-parent-{wildcard_parent}")
                    wildcard_data = f"_wildcard.{wildcard_parent}"
                    if wildcard_data != event.data:
                        if "target" in event.tags:
                            self.debug(
                                f'Wildcard detected for target "{event.data}" under "{wildcard_parent}"; keeping target data and tagging it as wildcard-child'
                            )
                            return False
                        self.debug(f'Wildcard detected, changing event.data "{event.data}" --> "{wildcard_data}"')
                        event.data = wildcard_data
                        return True
        return False

    async def emit_dns_children(self, event):
        for rdtype, children in event.dns_children.items():
            module = self._make_dummy_module(rdtype)
            for child_host in children:
                child_is_address_record_ip = rdtype in ("A", "AAAA") and self.helpers.is_ip(str(child_host))
                child_event_type = "IP_ADDRESS" if child_is_address_record_ip else "DNS_NAME"
                try:
                    child_event = self.scan.make_event(
                        child_host,
                        child_event_type,
                        module=module,
                        parent=event,
                        context=f"{rdtype} record for {event.host} contains {{event.type}}: {{event.host}}",
                    )
                except ValidationError as e:
                    self.warning(f'Event validation failed for DNS child of {event}: "{child_host}" ({rdtype}): {e}')
                    continue

                child_hash = hash(f"{event.host}:{module}:{child_event_type}:{child_host}")
                # if we haven't emitted this one before
                if child_hash not in self.children_emitted:
                    # and it's either in-scope or inside our dns search distance
                    child_is_in_scope = self.preset.in_scope(child_host)
                    parent_is_in_scope = event.scope_distance <= self.scan.scope_search_distance
                    if child_is_address_record_ip and parent_is_in_scope:
                        child_event.scope_distance = event.scope_distance
                    if (
                        child_is_in_scope
                        or (child_is_address_record_ip and parent_is_in_scope)
                        or (self.emit_out_of_scope_children and child_event.scope_distance <= self._dns_search_distance)
                    ):
                        self.children_emitted.add(child_hash)
                        # if it's a hostname and it's only one hop away, mark it as affiliate
                        if child_event.type == "DNS_NAME" and child_event.scope_distance == 1:
                            child_event.add_tag("affiliate")
                        self.debug(f"Queueing DNS child for {event}: {child_event}")
                        await self.emit_event(child_event)

    async def emit_dns_children_raw(self, event, dns_tags):
        for rdtype, answers in event.raw_dns_records.items():
            rdtype_lower = rdtype.lower()
            tags = {t for t in dns_tags if rdtype_lower in t.split("-")}
            if self.emit_raw_records and rdtype not in ("A", "AAAA", "CNAME", "PTR"):
                for answer in answers:
                    text_answer = answer.to_text()
                    child_hash = hash(f"{event.host}:{rdtype}:{text_answer}")
                    if child_hash not in self.children_emitted_raw:
                        self.children_emitted_raw.add(child_hash)
                        await self.emit_event(
                            {"host": str(event.host), "type": rdtype, "answer": text_answer},
                            "RAW_DNS_RECORD",
                            parent=event,
                            tags=tags,
                            context=f"{rdtype} lookup on {{event.parent.host}} produced {{event.type}}",
                        )

    async def emit_policy_events(self, event):
        host = str(event.host or "").strip().rstrip(".").lower()
        if not host or not self.helpers.is_domain(host):
            return
        if "_wildcard" in host.split("."):
            return
        if service_record(host) is True:
            return

        await self.emit_google_workspace_finding(event, host)
        await self.emit_caa_enrichments(event, host)
        await self.emit_dmarc_enrichments(event, host)
        await self.emit_tlsrpt_enrichments(event, host)
        await self.emit_bimi_enrichments(event, host)

    async def emit_google_workspace_finding(self, event, host):
        dedup_key = ("google-workspace", host)
        if dedup_key in self.policy_queries_done:
            return
        self.policy_queries_done.add(dedup_key)

        signals = set()
        for answer in event.raw_dns_records.get("TXT", set()):
            value = self.normalize_txt_answer(answer.to_text()).lower()
            if "include:_spf.google.com" in value:
                signals.add("spf-google")

        for answer in event.raw_dns_records.get("MX", set()):
            value = answer.to_text().strip().lower()
            if any(
                marker in value
                for marker in (
                    " smtp.google.com",
                    " aspmx.l.google.com",
                    ".googlemail.com",
                    ".google.com",
                )
            ):
                signals.add("mx-google")

        if not signals:
            return

        await self.emit_unique_policy_event(
            ("FINDING", host, "google-workspace"),
            {
                "host": host,
                "title": f"Google Workspace detected for {host}",
                "category": "domain-classification",
                "description": (
                    f"Google Workspace DNS signals were detected for {host}: {', '.join(sorted(signals))}. "
                    "This indicates the domain may use Google's hosted mail, identity, verification, or collaboration services. "
                    "The finding is informational, but it is useful for security review because identity and email providers are high-value control points. "
                    "Confirm that the tenant is owned by the organization, that abandoned domains are not still linked to active services, and that mail authentication, administrator access, multifactor authentication, and account recovery settings are managed intentionally. "
                    "Unexpected Workspace records can also reveal legacy migrations or forgotten SaaS configuration that should be cleaned up."
                ),
                "is_google_workspace": True,
                "signals": sorted(signals),
                "template": "dnsresolve-google-workspace",
            },
            "FINDING",
            event,
            ["domain-classification", "google-workspace"],
            f'{{module}} analyzed DNS for "{host}" and produced {{event.type}}',
        )

    async def emit_caa_enrichments(self, event, host):
        dedup_key = ("caa", host)
        if dedup_key in self.policy_queries_done:
            return
        self.policy_queries_done.add(dedup_key)

        answers = list(event.raw_dns_records.get("CAA", set()))
        if not answers:
            results = await self.helpers.resolve_raw(host, type="CAA")
            if results:
                raw_results, _errors = results
                answers = list(raw_results)

        for answer in answers:
            value = answer.to_text().strip().replace('" "', "")
            caa_match = caa_regex.search(value)
            if not caa_match or not caa_match.group("property") or not caa_match.group("text"):
                continue

            property_name = caa_match.group("property").lower()
            text = caa_match.group("text")
            tags = ["caa-record"]
            if property_name == "iodef":
                await self.emit_email_matches(event, host, text, tags)
                await self.emit_url_matches(event, host, text, tags)
            elif property_name.startswith("issue"):
                for match in dns_name_extraction_regex.finditer(text):
                    start, end = match.span()
                    dns_name = text[start:end]
                    await self.emit_unique_policy_event(
                        ("DNS_NAME", host, dns_name.lower(), property_name),
                        dns_name,
                        "DNS_NAME",
                        event,
                        tags,
                        f'{{module}} parsed a CAA record for "{host}" and found {{event.type}}: {{event.data}}',
                    )

    async def emit_dmarc_enrichments(self, event, host):
        dedup_key = ("dmarc", host)
        if dedup_key in self.policy_queries_done:
            return
        self.policy_queries_done.add(dedup_key)

        record_host = f"_dmarc.{host}"
        answers = await self.resolve_policy_txt_answers(event, record_host, ["dmarc-record"])
        for answer in answers:
            value = self.normalize_txt_answer(answer.to_text())
            dmarc_match = dmarc_regex.search(value)
            if not dmarc_match or not dmarc_match.group("kvps"):
                continue

            for kvp_match in dmarc_kvp_regex.finditer(dmarc_match.group("kvps")):
                key = kvp_match.group("k").lower()
                if key not in ("rua", "ruf"):
                    continue
                for candidate in [entry.strip() for entry in kvp_match.group("v").split(",") if entry.strip()]:
                    await self.emit_email_matches(event, record_host, candidate, ["dmarc-record", f"dmarc-record-{key}"])
                    await self.emit_url_matches(event, record_host, candidate, ["dmarc-record", f"dmarc-record-{key}"])

    async def emit_tlsrpt_enrichments(self, event, host):
        dedup_key = ("tlsrpt", host)
        if dedup_key in self.policy_queries_done:
            return
        self.policy_queries_done.add(dedup_key)

        record_host = f"_smtp._tls.{host}"
        answers = await self.resolve_policy_txt_answers(event, record_host, ["tlsrpt-record"])
        for answer in answers:
            value = self.normalize_txt_answer(answer.to_text())
            tlsrpt_match = tlsrpt_regex.search(value)
            if not tlsrpt_match or not tlsrpt_match.group("kvps"):
                continue

            for kvp_match in tlsrpt_kvp_regex.finditer(tlsrpt_match.group("kvps")):
                key = kvp_match.group("k").lower()
                if key != "rua":
                    continue
                for csul_match in csul.finditer(kvp_match.group("v")):
                    uri = csul_match.group("uri")
                    if not uri:
                        continue
                    await self.emit_email_matches(event, record_host, uri, ["tlsrpt-record", f"tlsrpt-record-{key}"])
                    await self.emit_url_matches(event, record_host, uri, ["tlsrpt-record", f"tlsrpt-record-{key}"])

    async def emit_bimi_enrichments(self, event, host):
        bimi_domains = [host]
        parent_domain = self.helpers.parent_domain(host)
        if parent_domain and parent_domain != host:
            bimi_domains.append(parent_domain)

        for bimi_domain in dict.fromkeys(bimi_domains):
            dedup_key = ("bimi", bimi_domain)
            if dedup_key in self.policy_queries_done:
                continue
            self.policy_queries_done.add(dedup_key)

            for selector in self.bimi_selectors:
                record_host = f"{selector}._bimi.{bimi_domain}"
                tags = ["bimi-record", f"bimi-{selector}"]
                answers = await self.resolve_policy_txt_answers(event, record_host, tags)
                for answer in answers:
                    value = self.normalize_txt_answer(answer.to_text())
                    bimi_values = self.parse_semicolon_kv_record(value)
                    if str(bimi_values.get("v", "")).upper() != "BIMI1":
                        continue

                    await self.emit_url_matches(event, record_host, value, tags)

                    location = str(bimi_values.get("l", "")).strip().rstrip(";,.")
                    if location:
                        await self.emit_unique_policy_event(
                            ("URL_UNVERIFIED", record_host, location, "bimi-location"),
                            location,
                            "URL_UNVERIFIED",
                            event,
                            tags + ["bimi-location"],
                            f'{{module}} parsed a BIMI record for "{record_host}" and found {{event.type}}: {{event.data}}',
                        )

                    authority = str(bimi_values.get("a", "")).strip().rstrip(";,.")
                    if authority:
                        await self.emit_unique_policy_event(
                            ("URL_UNVERIFIED", record_host, authority, "bimi-authority"),
                            authority,
                            "URL_UNVERIFIED",
                            event,
                            tags + ["bimi-authority"],
                            f'{{module}} parsed a BIMI record for "{record_host}" and found {{event.type}}: {{event.data}}',
                        )

    async def resolve_policy_txt_answers(self, event, hostname, tags):
        results = await self.helpers.resolve_raw(hostname, type="TXT")
        if not results:
            return []

        raw_results, _errors = results
        if self.emit_raw_records:
            for answer in raw_results:
                await self.emit_unique_policy_event(
                    ("RAW_DNS_RECORD", hostname, answer.to_text()),
                    {"host": hostname, "type": "TXT", "answer": answer.to_text()},
                    "RAW_DNS_RECORD",
                    event,
                    list(tags) + ["txt-record"],
                    f"TXT lookup on {hostname} produced {{event.type}}",
                )

        return list(raw_results)

    async def emit_email_matches(self, event, record_host, text, tags):
        for match in email_regex.finditer(text):
            start, end = match.span()
            email = text[start:end]
            await self.emit_unique_policy_event(
                ("EMAIL_ADDRESS", record_host, email.lower(), tuple(tags)),
                email,
                "EMAIL_ADDRESS",
                event,
                tags,
                f'{{module}} parsed DNS policy data for "{record_host}" and found {{event.type}}: {{event.data}}',
            )

    async def emit_url_matches(self, event, record_host, text, tags):
        matched_urls = []
        for url_regex in url_regexes:
            for match in url_regex.finditer(text):
                start, end = match.span()
                url = text[start:end].strip('"').strip().rstrip(";,.")
                matched_urls.append(url)

        if not matched_urls:
            matched_urls.extend(
                match.group(0).strip('"').strip().rstrip(";,.") for match in simple_url_regex.finditer(str(text or ""))
            )

        for url in dict.fromkeys(matched_urls):
            await self.emit_unique_policy_event(
                ("URL_UNVERIFIED", record_host, url, tuple(tags)),
                url,
                "URL_UNVERIFIED",
                event,
                tags,
                f'{{module}} parsed DNS policy data for "{record_host}" and found {{event.type}}: {{event.data}}',
            )

    async def emit_unique_policy_event(self, dedup_key, payload, event_type, parent, tags, context):
        if dedup_key in self.policy_events_emitted:
            return
        self.policy_events_emitted.add(dedup_key)
        await self.emit_event(payload, event_type, parent=parent, tags=tags, context=context)

    def normalize_txt_answer(self, value):
        text = str(value or "").strip()
        if ((text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'"))):
            return text[1:-1]
        return text.replace('" "', "").replace('"', "")

    def parse_semicolon_kv_record(self, value):
        parsed = {}
        for part in str(value or "").split(";"):
            if "=" not in part:
                continue
            key, raw_value = part.split("=", 1)
            key = key.strip().lower()
            if not key:
                continue
            parsed[key] = raw_value.strip()
        return parsed

    def check_scope(self, event):
        whitelisted = False
        blacklisted = False
        dns_children = getattr(event, "dns_children", {})
        for rdtype in ("A", "AAAA", "CNAME"):
            hosts = dns_children.get(rdtype, [])
            # update resolved hosts
            event.resolved_hosts.update(hosts)
            for host in hosts:
                # having a CNAME to an in-scope host doesn't make you in-scope
                if rdtype != "CNAME":
                    if not whitelisted:
                        with suppress(ValidationError):
                            if self.scan.whitelisted(host):
                                whitelisted = True
                                event.add_tag(f"dns-whitelisted-{rdtype}")
                # but a CNAME to a blacklisted host means you're blacklisted
                if not blacklisted:
                    with suppress(ValidationError):
                        if self.scan.blacklisted(host):
                            blacklisted = True
                            event.add_tag("blacklisted")
                            event.add_tag(f"dns-blacklisted-{rdtype}")
        if blacklisted:
            whitelisted = False
        return whitelisted, blacklisted

    async def resolve_event(self, event, types):
        if not types:
            return
        event_host = str(event.host)
        queries = [(event_host, rdtype) for rdtype in types]
        dns_errors = {}
        async for (query, rdtype), (answers, errors) in self.helpers.dns.resolve_raw_batch(queries):
            # errors
            try:
                dns_errors[rdtype].update(errors)
            except KeyError:
                dns_errors[rdtype] = set(errors)
            for answer in answers:
                event.add_tag(f"{rdtype}-record")
                # raw dnspython answers
                try:
                    event.raw_dns_records[rdtype].add(answer)
                except KeyError:
                    event.raw_dns_records[rdtype] = {answer}
                # hosts
                for _rdtype, host in extract_targets(answer):
                    try:
                        event.dns_children[_rdtype].add(host)
                    except KeyError:
                        event.dns_children[_rdtype] = {host}
                    # check for private IPs
                    try:
                        ip = ipaddress.ip_address(host)
                        if ip.is_private:
                            event.add_tag("private-ip")
                    except ValueError:
                        continue

        # tag event with errors
        for rdtype, errors in dns_errors.items():
            # only consider it an error if there weren't any results for that rdtype
            if errors and rdtype not in event.dns_children:
                event.add_tag(f"{rdtype}-error")

    def get_dns_parent(self, event):
        """
        Get the first parent DNS_NAME / IP_ADDRESS of an event. If one isn't found, create it.
        """
        for parent in event.get_parents(include_self=True):
            if parent.host == event.host and parent.type in ("IP_ADDRESS", "DNS_NAME", "DNS_NAME_UNRESOLVED"):
                blacklisted = any(t.startswith("dns-blacklisted-") for t in parent.tags)
                whitelisted = any(t.startswith("dns-whitelisted-") for t in parent.tags)
                new_event = parent is event
                return parent, whitelisted, blacklisted, new_event
        tags = set()
        if "target" in event.tags:
            tags.add("target")
        return (
            self.scan.make_event(
                event.host,
                "DNS_NAME",
                module=self.host_module,
                parent=event,
                context="{event.parent.type} has host {event.type}: {event.host}",
                tags=tags,
            ),
            None,
            None,
            True,
        )

    @property
    def emit_raw_records(self):
        if self._emit_raw_records is None:
            watching_raw_records = any("RAW_DNS_RECORD" in m.get_watched_events() for m in self.scan.modules.values())
            omitted_event_types = self.scan.config.get("omit_event_types", [])
            omit_raw_records = "RAW_DNS_RECORD" in omitted_event_types
            self._emit_raw_records = watching_raw_records or not omit_raw_records
        return self._emit_raw_records

    @property
    def _dns_search_distance(self):
        return max(self.scan.scope_search_distance, self.dns_search_distance)

    def _make_dummy_module(self, name):
        try:
            dummy_module = self.scan.dummy_modules[name]
        except KeyError:
            dummy_module = self.scan._make_dummy_module(name=name, _type="DNS")
            dummy_module._priority = 4
            dummy_module.suppress_dupes = False
            self.scan.dummy_modules[name] = dummy_module
        return dummy_module
