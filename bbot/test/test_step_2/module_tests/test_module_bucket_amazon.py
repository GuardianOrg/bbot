import re

from .base import ModuleTestBase
from bbot.core.helpers.misc import rand_string

__all__ = ["random_bucket_name_1", "random_bucket_name_2", "random_bucket_name_3", "Bucket_Amazon_Base"]

# first one is a normal bucket
random_bucket_name_1 = rand_string(15, digits=False)
# second one is open/vulnerable
random_bucket_name_2 = rand_string(15, digits=False)
# third one is a mutation
random_bucket_name_3 = f"{random_bucket_name_2}-dev"


class Bucket_Amazon_Base(ModuleTestBase):
    targets = ["http://127.0.0.1:8888"]
    provider = "amazon"

    random_bucket_1 = f"{random_bucket_name_1}.s3.amazonaws.com"
    random_bucket_2 = f"{random_bucket_name_2}.s3-ap-southeast-2.amazonaws.com"
    random_bucket_3 = f"{random_bucket_name_3}.s3.amazonaws.com"

    nonexistent_is_404 = True

    open_bucket_body = """<?xml version="1.0" encoding="UTF-8"?>
    <ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>vpn-static</Name><Prefix></Prefix><Marker></Marker><MaxKeys>1000</MaxKeys><IsTruncated>false</IsTruncated><Contents><Key>style.css</Key><LastModified>2017-03-18T06:41:59.000Z</LastModified><ETag>&quot;bf9e72bdab09b785f05ff0395023cc35&quot;</ETag><Size>429</Size><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"""

    @property
    def config_overrides(self):
        return {"modules": {self.module_name: {"permutations": True}}}

    @property
    def module_name(self):
        return self.__class__.__name__.lower().split("test")[-1]

    @property
    def modules_overrides(self):
        return ["excavate", "speculate", "httpx", self.module_name, "cloudcheck"]

    def url_setup(self):
        self.url_1 = f"https://{self.random_bucket_1}/"
        self.url_2 = f"https://{self.random_bucket_2}/"
        self.url_3 = f"https://{self.random_bucket_3}/"

    def bucket_setup(self):
        self.url_setup()
        self.website_body = f"""
        <a href="{self.url_1}"/>
        <a href="{self.url_2}"/>
        """

    async def setup_after_prep(self, module_test):
        self.bucket_setup()
        # patch mutations
        module_test.scan.helpers.word_cloud.mutations = lambda b, **kwargs: [
            (b, "dev"),
        ]
        module_test.set_expect_requests(
            expect_args={"method": "GET", "uri": "/"}, respond_args={"response_data": self.website_body}
        )
        if module_test.module.supports_open_check:
            module_test.httpx_mock.add_response(
                url=self.url_2,
                text=self.open_bucket_body,
            )
            if self.module_name == "bucket_amazon":
                module_test.httpx_mock.add_response(
                    url=self.url_2.rstrip("/"),
                    text=self.open_bucket_body,
                )
            elif self.module_name == "bucket_firebase":
                module_test.httpx_mock.add_response(
                    url=self.url_2,
                    text=self.open_bucket_body,
                )
                module_test.httpx_mock.add_response(
                    url=f"{self.url_2.rstrip('/')}/.json",
                    text=self.open_bucket_body,
                )
                module_test.httpx_mock.add_response(
                    url=f"{self.url_2.rstrip('/')}/.json",
                    text=self.open_bucket_body,
                )
            elif self.module_name == "bucket_google":
                permissions = "&".join(["=".join(("permissions", p)) for p in module_test.module.bad_permissions])
                module_test.httpx_mock.add_response(
                    url=f"https://www.googleapis.com/storage/v1/b/{random_bucket_name_2}/iam/testPermissions?{permissions}",
                    json={"permissions": module_test.module.bad_permissions},
                )
            elif self.module_name == "bucket_microsoft":
                module_test.httpx_mock.add_response(
                    url=f"https://{random_bucket_name_2}.blob.core.windows.net/{random_bucket_name_2}?restype=container&comp=list",
                    text=self.open_bucket_body,
                )
        module_test.httpx_mock.add_response(
            url=self.url_3,
            text="",
        )
        if self.module_name == "bucket_amazon":
            module_test.httpx_mock.add_response(
                url=f"{self.url_3.rstrip('/')}/index.html",
                text="",
            )
        if self.nonexistent_is_404:
            module_test.httpx_mock.add_response(url=re.compile(".*"), text="", status_code=404)

    def check(self, module_test, events):
        storage_buckets = [e for e in events if e.type == "STORAGE_BUCKET"]
        assert len(storage_buckets) == 3
        assert 1 == len(
            [
                e
                for e in storage_buckets
                if e.data["name"] == random_bucket_name_1
                and str(e.module) == "cloudcheck"
                and f"cloud-{self.provider}" in e.tags
                and f"{self.provider}-domain" in e.tags
            ]
        )
        assert 1 == len(
            [
                e
                for e in storage_buckets
                if e.data["name"] == random_bucket_name_2
                and str(e.module) == "cloudcheck"
                and f"cloud-{self.provider}" in e.tags
                and f"{self.provider}-domain" in e.tags
            ]
        )
        assert 1 == len(
            [
                e
                for e in storage_buckets
                if e.data["name"] == random_bucket_name_3
                and e.data["provider"] == module_test.module.provider_slug
                and e.data["resource_type"] == "storage_bucket"
                and e.data["is_public"] is False
                and str(e.module) == str(self.module_name)
                and f"cloud-{module_test.module.cloudcheck_provider_name.lower()}" in e.tags
                and f"{module_test.module.cloudcheck_provider_name.lower()}-domain" in e.tags
            ]
        )
        if self.module_name == "bucket_amazon":
            regional_bucket = next(e for e in storage_buckets if e.data["name"] == random_bucket_name_2)
            assert regional_bucket.data.get("region") == "ap-southeast-2"
        if self.module_name == "bucket_digitalocean":
            module_bucket = next(e for e in storage_buckets if e.data["name"] == random_bucket_name_3)
            assert module_bucket.data.get("region") == "fra1"
        # make sure open buckets were found
        if module_test.module.supports_open_check:
            assert 1 == len(
                [
                    e
                for e in events
                if e.type == "FINDING"
                and str(e.module) == self.module_name
                and str(e.data.get("url", "")).rstrip("/") == f"https://{self.random_bucket_2}".rstrip("/")
                and e.data.get("provider") == module_test.module.provider_slug
                and e.data.get("resource_type") == "storage_bucket"
                and e.data.get("bucket_name") == random_bucket_name_2
                and e.data.get("is_public") is True
                and any(p in e.data.get("permissions", []) for p in ("read", "list", "write", "delete", "admin"))
                ]
            ), f'open bucket not found for module "{self.module_name}"'
        # make sure bucket mutations were found
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "STORAGE_BUCKET"
                and str(e.module) == self.module_name
                and f"{random_bucket_name_3}" in e.data["url"]
            ]
        ), f'bucket (dev mutation: {self.random_bucket_3}) not found for module "{self.module_name}"'


class TestBucket_Amazon(Bucket_Amazon_Base):
    pass
