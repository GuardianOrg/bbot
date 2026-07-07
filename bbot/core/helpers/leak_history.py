import hashlib
import json
import re
from pathlib import Path

# A value that already looks like a stored hash (md5/sha1/sha256/ntlm/...) — we keep it as
# is rather than re-hashing, so the same hash compares equal across runs and sources.
_LOOKS_LIKE_HASH = re.compile(r"^[a-f0-9]{16,}$")


def _canonical(value):
    if value is None:
        return ""
    return re.sub(r"\s+", " ", str(value).strip().lower())


def secret_hash(secret):
    """Return a stable, non-reversible hash for a leaked secret.

    If the value already looks like a hash it is kept (lowercased); otherwise the cleartext
    is sha256'd so plaintext is never persisted in the history file.
    """
    if secret is None:
        return ""
    text = str(secret).strip()
    if not text:
        return ""
    if _LOOKS_LIKE_HASH.match(text.lower()):
        return text.lower()
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def leak_fingerprint(source, breach, username, secret, scope=None):
    """Stable fingerprint of a single leaked record, used to dedup across scans.

    Keyed on source + scope + breach + username + secret hash so the same leak is only
    reported once. A null username/secret (e.g. a public breach-name-only hit) yields a
    breach-level fingerprint; `scope` (e.g. the queried domain) then keeps that breach
    hit distinct per domain when a single history file is shared across a scan.
    """
    parts = [_canonical(source), _canonical(scope), _canonical(breach), _canonical(username), secret_hash(secret)]
    return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()


def _distinct_canonical(*collections):
    values = set()
    for collection in collections:
        for value in collection or []:
            canonical = _canonical(value)
            if canonical:
                values.add(canonical)
    return sorted(values)


def record_fingerprint(source, breach, emails=None, usernames=None, passwords=None, hashes=None):
    """Fingerprint of a single leaked record over ALL of its identities and secrets.

    Unlike leak_fingerprint (one identity + one secret) this covers every email/username
    and every password/hash on the record, so two records that merely share their first
    sorted value are still treated as distinct (no silent record loss). Secrets are hashed
    via secret_hash so plaintext is never persisted. Shared by both leak modules so their
    dedup stays identical.
    """
    identities = _distinct_canonical(emails, usernames)
    secrets = sorted({secret_hash(value) for value in list(passwords or []) + list(hashes or []) if secret_hash(value)})
    parts = [_canonical(source), _canonical(breach), ",".join(identities), ",".join(secrets)]
    return hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()


class LeakHistory:
    """Persistent set of already-reported leak fingerprints (a JSON list on disk).

    Leak modules use it to avoid re-emitting the same leak on later scans. When no path is
    configured it is a no-op (never suppresses), preserving the modules' default behavior.
    """

    def __init__(self, path="", warn=None):
        self.path = str(path or "").strip()
        # Optional warning sink (e.g. a module's self.warning) so a corrupt/unwritable
        # history file is surfaced instead of silently re-alerting every leak next scan.
        self._warn = warn
        self.fingerprints = set()
        self._load()

    def _load(self):
        if not self.path:
            return
        try:
            with open(self.path) as handle:
                data = json.load(handle)
            if isinstance(data, list):
                self.fingerprints = {str(item) for item in data if item}
        except FileNotFoundError:
            pass
        except Exception as error:
            # A corrupt file would otherwise reset history to empty and re-alert everything.
            if self._warn:
                self._warn(f"Could not read leak history {self.path}: {error}")

    def contains(self, fingerprint):
        return bool(self.path) and fingerprint in self.fingerprints

    def add(self, fingerprint):
        if self.path:
            self.fingerprints.add(fingerprint)

    def save(self):
        if not self.path:
            return
        try:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
            with open(self.path, "w") as handle:
                json.dump(sorted(self.fingerprints), handle)
        except Exception as error:
            # A failed write silently repeats forever; make it visible.
            if self._warn:
                self._warn(f"Could not write leak history {self.path}: {error}")
