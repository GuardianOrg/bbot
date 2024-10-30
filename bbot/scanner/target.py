import copy
import logging
import regex as re
from hashlib import sha1
from radixtarget import RadixTarget
from radixtarget.helpers import host_size_key

from bbot.errors import *
from bbot.core.event import make_event, is_event

log = logging.getLogger("bbot.core.target")


def special_target_type(regex_pattern):
    def decorator(func):
        func._regex = re.compile(regex_pattern, re.IGNORECASE)
        return func

    return decorator


class BaseTarget(RadixTarget):
    """
    A collection of BBOT events that represent a scan target.

    Based on radixtarget, which allows extremely fast IP and DNS lookups.

    This class is inherited by all three components of the BBOT target:
        - Whitelist
        - Blacklist
        - Seeds
    """

    special_target_types = {
        # regex-callback pairs for handling special target types
        # these aren't defined explicitly; instead they are decorated with @special_target_type
        # the function must return a list of events
    }
    tags = []

    def __init__(self, *targets, scan=None, **kwargs):
        self.scan = scan
        self.events = set()
        super().__init__(**kwargs)
        # we preserve the raw inputs to ensure we don't lose any information
        self.inputs, events = self._make_events(targets)
        # sort by host size to ensure consistency
        events = sorted(events, key=lambda e: (0 if not e.host else host_size_key(e.host)))
        for event in events:
            if event.host:
                self._add(event.host, data=event)
            else:
                self.events.add(event)
        # Register decorated methods
        for method in dir(self):
            if callable(getattr(self, method)):
                func = getattr(self, method)
                if hasattr(func, "_regex"):
                    self.special_target_types[func._regex] = func

    def get(self, event, single=True, **kwargs):
        event = self.make_event(event)
        results = super().get(event.host, **kwargs)
        if results and single:
            return next(iter(results))
        return results

    def make_event(self, *args, **kwargs):
        # if it's already an event, return it
        if args and is_event(args[0]):
            return args[0]
        # otherwise make a new one
        if not "tags" in kwargs:
            kwargs["tags"] = set()
        kwargs["tags"].update(self.tags)
        return make_event(*args, dummy=True, scan=self.scan, **kwargs)

    def _add(self, host, data=None):
        """
        Overrides the base method to enable having multiple events for the same host.

        The "data" attribute of the node is now a set of events.
        """
        if data is None:
            event = self.make_event(host)
        else:
            event = data
        self.events.add(event)
        if event.host:
            try:
                event_set = self.get(event.host, single=False, raise_error=True)
                event_set.add(event)
            except KeyError:
                event_set = {event}
                super()._add(event.host, data=event_set)
        return event

    def _make_events(self, targets):
        inputs = set()
        events = set()
        for target in targets:
            _events = []
            special_target_type, _events = self.check_special_target_types(str(target))
            if special_target_type:
                inputs.add(str(target))
            else:
                event = self.make_event(target)
                if event:
                    _events = [event]
            for event in _events:
                inputs.add(event.data)
                events.add(event)
        return inputs, events

    def check_special_target_types(self, target):
        for regex, callback in self.special_target_types.items():
            match = regex.match(target)
            if match:
                return True, callback(match)
        return False, []

    def __iter__(self):
        yield from self.events


class ScanSeeds(BaseTarget):
    """
    Initial events used to seed a scan.

    These are the targets specified by the user, e.g. via `-t` on the CLI.
    """

    tags = ["target"]

    @special_target_type(r"^(?:ORG|ORG_STUB):(.*)")
    def handle_org_stub(self, match):
        org_stub_event = self.make_event(match.group(1), event_type="ORG_STUB")
        if org_stub_event:
            return [org_stub_event]
        return []

    @special_target_type(r"^(?:USER|USERNAME):(.*)")
    def handle_username(self, match):
        username_event = self.make_event(match.group(1), event_type="USERNAME")
        if username_event:
            return [username_event]
        return []


class ScanWhitelist(BaseTarget):
    """
    A collection of BBOT events that represent a scan's whitelist.
    """

    def __init__(self, *args, **kwargs):
        kwargs["acl_mode"] = True
        super().__init__(*args, **kwargs)


class ScanBlacklist(BaseTarget):
    """
    A collection of BBOT events that represent a scan's blacklist.
    """

    def __init__(self, *args, **kwargs):
        self.blacklist_regexes = set()
        super().__init__(*args, **kwargs)

    @special_target_type(r"^(?:RE|REGEX):(.*)")
    def handle_regex(self, match):
        pattern = match.group(1)
        blacklist_regex = re.compile(pattern, re.IGNORECASE)
        self.blacklist_regexes.add(blacklist_regex)
        return []

    def get(self, event, **kwargs):
        """
        Here, for the blacklist, we modify this method to also consider any special regex patterns specified by the user
        """
        event = self.make_event(event)
        # first, check event's host against blacklist
        event_result = super().get(event, **kwargs)
        if event_result is not None:
            return event_result
        # next, check event's host against regexes
        host_or_url = event.host_filterable
        for regex in self.blacklist_regexes:
            if regex.match(host_or_url):
                return event
        return None


class BBOTTarget:
    """
    A convenient abstraction of a scan target that contains three subtargets:
        - seeds
        - whitelist
        - blacklist

    Provides high-level functions like in_scope(), which includes both whitelist and blacklist checks.
    """

    def __init__(self, *seeds, whitelist=None, blacklist=None, strict_scope=False, scan=None):
        self.scan = scan
        self.strict_scope = strict_scope
        self.seeds = ScanSeeds(*seeds, strict_dns_scope=strict_scope, scan=scan)
        if whitelist is None:
            whitelist = self.seeds.hosts
        self.whitelist = ScanWhitelist(*whitelist, strict_dns_scope=strict_scope, scan=scan)
        if blacklist is None:
            blacklist = []
        self.blacklist = ScanBlacklist(*blacklist, scan=scan)

    @property
    def json(self):
        return {
            "seeds": sorted([e.data for e in self.seeds]),
            "whitelist": sorted([e.data for e in self.whitelist]),
            "blacklist": sorted([e.data for e in self.blacklist]),
            "strict_scope": self.strict_scope,
            "hash": self.hash.hex(),
            "seed_hash": self.seeds.hash.hex(),
            "whitelist_hash": self.whitelist.hash.hex(),
            "blacklist_hash": self.blacklist.hash.hex(),
            "scope_hash": self.scope_hash.hex(),
        }

    @property
    def hash(self):
        sha1_hash = sha1()
        for target_hash in [t.hash for t in (self.seeds, self.whitelist, self.blacklist)]:
            sha1_hash.update(target_hash)
        return sha1_hash.digest()

    @property
    def scope_hash(self):
        sha1_hash = sha1()
        # Consider only the hash values of the whitelist and blacklist
        for target_hash in [t.hash for t in (self.whitelist, self.blacklist)]:
            sha1_hash.update(target_hash)
        return sha1_hash.digest()

    def copy(self):
        self_copy = copy.copy(self)
        self_copy.seeds = self.seeds.copy()
        self_copy.whitelist = self.whitelist.copy()
        self_copy.blacklist = self.blacklist.copy()
        return self_copy

    def in_scope(self, host):
        """
        Check whether a hostname, url, IP, etc. is in scope.
        Accepts either events or string data.

        Checks whitelist and blacklist.
        If `host` is an event and its scope distance is zero, it will automatically be considered in-scope.

        Examples:
            Check if a URL is in scope:
            >>> preset.in_scope("http://www.evilcorp.com")
            True
        """
        try:
            e = make_event(host, dummy=True)
        except ValidationError:
            return False
        in_scope = e.scope_distance == 0 or self.whitelisted(e)
        return in_scope and not self.blacklisted(e)

    def blacklisted(self, host):
        """
        Check whether a hostname, url, IP, etc. is blacklisted.

        Note that `host` can be a hostname, IP address, CIDR, email address, or any BBOT `Event` with the `host` attribute.

        Args:
            host (str or IPAddress or Event): The host to check against the blacklist

        Examples:
            Check if a URL's host is blacklisted:
            >>> preset.blacklisted("http://www.evilcorp.com")
            True
        """
        return host in self.blacklist

    def whitelisted(self, host):
        """
        Check whether a hostname, url, IP, etc. is whitelisted.

        Note that `host` can be a hostname, IP address, CIDR, email address, or any BBOT `Event` with the `host` attribute.

        Args:
            host (str or IPAddress or Event): The host to check against the whitelist

        Examples:
            Check if a URL's host is whitelisted:
            >>> preset.whitelisted("http://www.evilcorp.com")
            True
        """
        return host in self.whitelist

    @property
    def minimal(self):
        """
        A slimmer, serializable version of the target designed for simple scope checks

        This version doesn't have the events, only their hosts. This allows it to be passed across process boundaries.
        """
        return self.__class__(
            seeds=[],
            whitelist=self.whitelist.inputs,
            blacklist=self.blacklist.inputs,
            strict_scope=self.strict_scope,
        )
