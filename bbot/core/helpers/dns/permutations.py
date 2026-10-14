"""Bounded callers can consume DNSGen's static rules without its shared WORDS global."""

import importlib
from collections import deque
from types import FunctionType


def iter_dnsgen_candidates(host, root, words):
    engine = importlib.import_module("dnsgen.dnsgen")
    labels = host[: -(len(root) + 1)].split(".") if host != root else []
    # DNSGen 1.0.4 treats the registrable label and public suffix as the last two parts.
    # Use BBOT's root here so multi-label suffixes and nested scan scopes stay intact.
    parts = labels + root.split(".", 1)
    globals_for_scan = {**engine.__dict__, "WORDS": list(words), "NUM_COUNT": 3}
    rules = [FunctionType(rule.__code__, globals_for_scan) for rule in engine.PERMUTATOR.members]
    streams = deque([iter(_replace_labels(labels, root, words))])
    # Round-robin prevents the insertion rule from consuming the entire seed budget.
    streams.extend(iter(rule(parts)) for rule in rules)
    while streams:
        stream = streams.popleft()
        try:
            yield next(stream)
        except StopIteration:
            continue
        streams.append(stream)


def _replace_labels(labels, root, words):
    # DNSGen's substring replacement ignores words <= 3 characters (api/dev/eu/us).
    # Add exact label/token replacement so short environment and region names work too.
    for word in words:
        for index, label in enumerate(labels):
            if label != word:
                replaced = list(labels)
                replaced[index] = word
                yield ".".join(replaced + [root])
            tokens = label.split("-")
            if len(tokens) > 1:
                for token_index, token in enumerate(tokens):
                    if token != word:
                        replaced_tokens = list(tokens)
                        replaced_tokens[token_index] = word
                        replaced = list(labels)
                        replaced[index] = "-".join(replaced_tokens)
                        yield ".".join(replaced + [root])
