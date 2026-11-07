"""Bucket names guessed from an in-scope host must carry the whole host, not only its first label."""

import asyncio
import types

from bbot.core.helpers import misc
from bbot.modules.templates.bucket import bucket_template


def guessed_bucket_names(hostname):
    tried = []

    async def brute_buckets(buckets, permutations=False, omit_base=False):
        tried.extend(buckets)
        return
        yield

    module = types.SimpleNamespace(
        helpers=types.SimpleNamespace(
            unidecode=misc.unidecode,
            smart_decode_punycode=misc.smart_decode_punycode,
            domain_stem=misc.domain_stem,
        ),
        delimiters=bucket_template.delimiters,
        permutations=False,
        brute_buckets=brute_buckets,
    )
    event = types.SimpleNamespace(data=hostname)
    asyncio.run(bucket_template.handle_dns_name(module, event))
    return set(tried)


def test_a_bare_domain_stem_is_not_guessed_as_a_bucket_of_the_target():
    # A public bucket named "guardian" or "api-guardian" can belong to anyone.
    assert guessed_bucket_names("guardian.security") == {"guardiansecurity", "guardian.security", "guardian-security"}
    assert guessed_bucket_names("api.guardian.security") == {
        "apiguardiansecurity",
        "api.guardian.security",
        "api-guardian-security",
    }
