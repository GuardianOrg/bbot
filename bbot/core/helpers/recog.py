"""Match service banners against Rapid7 Recog fingerprint databases.

Recog (https://github.com/rapid7/recog, BSD-2) ships one XML database per
banner kind: ``ssh_banners.xml`` for the text after ``SSH-2.0-``, ``http_servers.xml``
for HTTP ``Server`` headers, and so on. Each fingerprint is a Ruby regex plus
params that either capture a group (``pos > 0``) or set a literal value that
may interpolate other params (``cpe:/a:openbsd:openssh:{service.version}``).
The first fingerprint that matches wins, as in Recog itself.
"""

import re
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

log = logging.getLogger("bbot.core.helpers.recog")

# Ruby's ^ and $ always anchor at line boundaries; its MULTILINE flag is Python's DOTALL.
_RUBY_FLAGS = {"REG_ICASE": re.I, "REG_DOT_NEWLINE": re.S, "REG_MULTILINE": re.S}
_PLACEHOLDER = re.compile(r"\{([a-z0-9_.]+)\}")


def ruby_to_python_regex(pattern):
    """Translate the Ruby regex syntax Recog uses into Python's."""
    pattern = pattern.replace(r"\Z", r"(?=\n?\Z)").replace(r"\z", r"\Z")
    pattern = re.sub(r"\(\?<(?![=!])", "(?P<", pattern)
    return pattern.replace(r"\h", "[0-9a-fA-F]")


class RecogFingerprint:
    __slots__ = ("regex", "params")

    def __init__(self, regex, params):
        self.regex = regex
        self.params = params

    def match(self, text):
        m = self.regex.search(text)
        if m is None:
            return None
        values = {}
        for pos, name, value in self.params:
            if pos:
                if pos <= len(m.groups()) and m.group(pos) is not None:
                    values[name] = m.group(pos)
            elif value is not None:
                values[name] = value
        return {name: _interpolate(value, values) for name, value in values.items()}


def _interpolate(value, values):
    """Fill ``{param}`` placeholders; a CPE whose placeholder is unknown keeps only its known prefix."""
    if "{" not in value:
        return value
    filled = _PLACEHOLDER.sub(lambda m: values.get(m.group(1), m.group(0)), value)
    if "{" in filled and filled.startswith("cpe:"):
        filled = filled.split(":{", 1)[0]
    return filled


class RecogDatabase:
    """One Recog XML file, compiled once."""

    def __init__(self, path):
        self.path = Path(path)
        self.fingerprints = []
        self.skipped = 0
        for fp in ET.parse(self.path).getroot().iter("fingerprint"):
            flags = re.M
            for flag in (fp.get("flags") or "").split(","):
                flags |= _RUBY_FLAGS.get(flag.strip(), 0)
            try:
                regex = re.compile(ruby_to_python_regex(fp.get("pattern", "")), flags)
            except re.error:
                self.skipped += 1
                continue
            params = [(int(p.get("pos") or 0), p.get("name"), p.get("value")) for p in fp.iter("param")]
            self.fingerprints.append(RecogFingerprint(regex, params))
        if self.skipped:
            log.debug(f"Recog {self.path.name}: skipped {self.skipped:,} patterns Python cannot compile")

    def match(self, text):
        if not text:
            return None
        for fingerprint in self.fingerprints:
            values = fingerprint.match(text)
            if values is not None:
                return values
        return None


class Recog:
    """Recog databases from one ``xml`` directory, loaded on first use."""

    def __init__(self, xml_dir):
        self.xml_dir = Path(xml_dir)
        self._databases = {}

    def database(self, name):
        if name not in self._databases:
            self._databases[name] = RecogDatabase(self.xml_dir / f"{name}.xml")
        return self._databases[name]

    def match(self, name, text):
        return self.database(name).match(text)
