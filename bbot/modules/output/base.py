import logging
import json
from pathlib import Path
from bbot.modules.base import BaseModule


class BaseOutputModule(BaseModule):
    accept_dupes = True
    _type = "output"
    scope_distance_modifier = None
    _stats_exclude = True
    _shuffle_incoming_queue = False

    hidden_report_tag_prefixes = ("distance-",)
    host_report_tags = {"cloud", "cdn"}
    host_report_tag_prefixes = ("cloud-", "cdn-")
    host_report_tag_suffixes = ("-domain", "-ip", "-cname")

    def human_event_str(self, event):
        event_type = f"[{event.type}]"
        host_display = self.report_host_display(event)
        data_display = event.data_human
        event_tags = self.report_event_tags(event)
        event_tags_str = f"\t({', '.join(event_tags)})" if event_tags else ""
        event_str = f"{event_type:<20}\t{host_display}\t{data_display}\t{event.module_sequence}{event_tags_str}"
        return event_str

    def is_hidden_report_tag(self, tag):
        tag = str(tag)
        return any(tag.startswith(prefix) for prefix in self.hidden_report_tag_prefixes)

    def is_host_report_tag(self, tag):
        tag = str(tag)
        if tag in self.host_report_tags:
            return True
        if any(tag.startswith(prefix) for prefix in self.host_report_tag_prefixes):
            return True
        if any(tag.endswith(suffix) for suffix in self.host_report_tag_suffixes):
            return True
        return False

    def split_report_tags(self, event):
        host_tags = []
        event_tags = []
        for tag in sorted(getattr(event, "tags", [])):
            if self.is_hidden_report_tag(tag):
                continue
            if self.is_host_report_tag(tag):
                host_tags.append(tag)
            else:
                event_tags.append(tag)
        return host_tags, event_tags

    def report_event_tags(self, event):
        _, event_tags = self.split_report_tags(event)
        return event_tags

    def report_host_tags(self, event):
        host_tags, _ = self.split_report_tags(event)
        return host_tags

    def report_host_display(self, event):
        host = str(getattr(event, "host", "") or "")
        host_tags = self.report_host_tags(event)
        if host and host_tags:
            return f"{host} ({', '.join(host_tags)})"
        if host:
            return host
        return "-"

    def _event_precheck(self, event):
        reason = "precheck succeeded"
        # special signal event types
        if event.type in ("FINISHED",):
            return True, "its type is FINISHED"
        if self.errored:
            return False, "module is in error state"
        # exclude non-watched types
        if not any(t in self.get_watched_events() for t in ("*", event.type)):
            return False, "its type is not in watched_events"
        if self.target_only:
            if "target" not in event.tags:
                return False, "it did not meet target_only filter criteria"

        ### begin output-module specific ###

        # force-output certain events to the graph
        if self._is_graph_important(event):
            return True, "event is critical to the graph"

        # omit certain event types
        if event._omit:
            if event.type in self.get_watched_events():
                reason = "its type is explicitly in watched_events"
                self.debug(f"Allowing omitted event: {event} because {reason}")
            else:
                return False, "its type is omitted in the config"

        # internal events like those from speculate, ipneighbor
        # or events that are over our report distance
        if event._internal:
            return False, "event is internal and output modules don't accept internal events"

        return True, reason

    async def _event_postcheck(self, event):
        acceptable, reason = await super()._event_postcheck(event)
        if acceptable and not event._stats_recorded and event.type not in ("FINISHED",):
            event._stats_recorded = True
            self.scan.stats.event_produced(event)
        return acceptable, reason

    def is_incoming_duplicate(self, event, add=False):
        is_incoming_duplicate, reason = super().is_incoming_duplicate(event, add=add)
        # make exception for graph-important events
        if self._is_graph_important(event):
            return False, "event is graph-important"
        return is_incoming_duplicate, reason

    def _prep_output_dir(self, filename):
        self.output_file = self.config.get("output_file", "")
        if self.output_file:
            self.output_file = Path(self.output_file)
        else:
            self.output_file = self.scan.home / str(filename)
        self.helpers.mkdir(self.output_file.parent)
        self._file = None

    def _scope_distance_check(self, event):
        return True, ""

    @property
    def file(self):
        if getattr(self, "_file", None) is None:
            self._file = open(self.output_file, mode="a")
        return self._file

    @property
    def log(self):
        if self._log is None:
            self._log = logging.getLogger(f"bbot.modules.output.{self.name}")
        return self._log

    def scan_input_dict(self):
        target = getattr(self.scan, "target", None)
        if target is None:
            return {"seeds": [], "whitelist": [], "blacklist": [], "strict_scope": False}
        return {
            "seeds": sorted(getattr(getattr(target, "seeds", None), "inputs", []) or []),
            "whitelist": sorted(getattr(getattr(target, "whitelist", None), "inputs", []) or []),
            "blacklist": sorted(getattr(getattr(target, "blacklist", None), "inputs", []) or []),
            "strict_scope": bool(getattr(target, "strict_scope", False)),
        }

    def scan_input_json(self):
        return json.dumps(self.scan_input_dict(), sort_keys=True)

    def scan_input_text(self, prefix="# "):
        return f"{prefix}Scan Input: {self.scan_input_json()}"
