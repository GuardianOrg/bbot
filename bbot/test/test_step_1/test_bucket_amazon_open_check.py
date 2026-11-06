import asyncio
from types import SimpleNamespace

from bbot.modules.bucket_amazon import bucket_amazon

ACCESS_DENIED = (
    '<?xml version="1.0" encoding="UTF-8"?><Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>'
)
LISTING = (
    '<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
    "<Name>site</Name><IsTruncated>false</IsTruncated></ListBucketResult>"
)


def check_open(responses):
    class TestBucketAmazon(bucket_amazon):
        @property
        def helpers(self):
            async def request(url):
                status_code, text = responses.get(url, (404, ""))
                return SimpleNamespace(status_code=status_code, text=text, headers={})

            return SimpleNamespace(request=request)

        def gen_tags_exists(self, response):
            return set()

    module = object.__new__(TestBucketAmazon)
    return asyncio.run(module.check_bucket_open("site", "https://site.s3.amazonaws.com/index.html"))


def test_public_index_with_listing_denied_is_a_static_website_not_an_open_bucket():
    msg, _tags, data = check_open(
        {
            "https://site.s3.amazonaws.com": (403, ACCESS_DENIED),
            "https://site.s3.amazonaws.com/index.html": (200, "<html>Welcome</html>"),
            "https://site.s3.amazonaws.com/robots.txt": (200, "User-agent: *"),
        }
    )

    assert msg == ""
    assert data == {}


def test_listable_bucket_is_open_even_when_empty():
    msg, _tags, data = check_open({"https://site.s3.amazonaws.com": (200, LISTING)})

    assert msg == "Open storage bucket"
    assert data == {"permissions": ["read", "list"]}
