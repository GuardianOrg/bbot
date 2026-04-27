from bbot.modules.templates.bucket import bucket_template


class bucket_microsoft(bucket_template):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    meta = {
        "description": "Check for Azure storage blobs related to target",
        "created_date": "2022-11-04",
        "author": "@TheTechromancer",
    }
    options = {
        "permutations": True,
        "max_candidates": 5000,
        "permutation_numbers": 0,
        "permutation_letters": False,
        "expand_found_buckets": False,
    }
    options_desc = {
        "permutations": "Whether to try permutations",
        "max_candidates": "Maximum number of bucket-name candidates to check per brute-force pass",
        "permutation_numbers": "How many numeric mutations to generate when permutations are enabled",
        "permutation_letters": "Whether to generate single-letter modifier permutations",
        "expand_found_buckets": "Whether to recursively mutate discovered bucket names for more bucket guesses",
    }

    cloudcheck_provider_name = "Microsoft"
    delimiters = ("", "-")
    base_domains = ["blob.core.windows.net"]
    supports_open_check = True

    def build_bucket_request(self, bucket_name, base_domain, region):
        url = self.build_url(bucket_name, base_domain, region)
        url = url.strip("/") + f"/{bucket_name}?restype=container"
        return url, {}

    def check_bucket_exists(self, bucket_name, response):
        status_code = getattr(response, "status_code", 0)
        existent_bucket = status_code in (200, 403, 409)
        return existent_bucket, set()

    async def check_bucket_exists_secondary(self, bucket_name, url, response):
        for candidate in ("index.html", "robots.txt", "favicon.ico"):
            probe_url = f"https://{bucket_name}.blob.core.windows.net/{candidate}"
            probe = await self.helpers.request(probe_url)
            if getattr(probe, "status_code", 0) == 200:
                return True, set()
        return False, set()

    async def check_bucket_open(self, bucket_name, url):
        list_url = f"https://{bucket_name}.blob.core.windows.net/{bucket_name}?restype=container&comp=list"
        response = await self.helpers.request(list_url)
        status_code = getattr(response, "status_code", 0)
        if status_code == 200:
            return ("Open storage bucket", set())

        for candidate in ("index.html", "robots.txt", "favicon.ico"):
            probe_url = f"https://{bucket_name}.blob.core.windows.net/{candidate}"
            probe = await self.helpers.request(probe_url)
            if getattr(probe, "status_code", 0) == 200:
                return (f"Open storage bucket (public object: {candidate})", set())
        return ("", set())

    def clean_bucket_url(self, url):
        # only return root URL
        return "/".join(url.split("/")[:3])
