from bbot.modules.templates.bucket import bucket_template


class bucket_amazon(bucket_template):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    meta = {
        "description": "Check for S3 buckets related to target",
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
    scope_distance_modifier = 3

    cloudcheck_provider_name = "Amazon"
    delimiters = ("", ".", "-")
    base_domains = ["s3.amazonaws.com"]
    regions = [None]
    supports_open_check = True

    def build_bucket_request(self, bucket_name, base_domain, region):
        return f"https://{bucket_name}.{base_domain}/index.html", {}

    def clean_bucket_url(self, url):
        return url.removesuffix("/index.html")

    def check_bucket_exists(self, bucket_name, response):
        status_code = getattr(response, "status_code", 0)
        content = getattr(response, "text", "")
        if status_code in (200, 403):
            return True, set()
        if status_code == 404 and "NoSuchKey" in content:
            return True, set()
        return False, set()

    async def check_bucket_exists_secondary(self, bucket_name, url, response):
        base_url = self.clean_bucket_url(url).rstrip("/")
        for candidate in ("index.html", "robots.txt", "favicon.ico"):
            probe_url = f"{base_url}/{candidate}"
            probe = await self.helpers.request(probe_url)
            status_code = getattr(probe, "status_code", 0)
            probe_text = getattr(probe, "text", "")
            if status_code == 200:
                return True, set()
            if status_code == 403:
                return True, set()
            if status_code == 404 and "NoSuchKey" in probe_text:
                return True, set()
        return False, set()

    async def check_bucket_open(self, bucket_name, url):
        base_url = self.clean_bucket_url(url).rstrip("/")
        response = await self.helpers.request(base_url)
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        content = getattr(response, "text", "")
        if status_code == 200 and "Contents" in content:
            return ("Open storage bucket", tags)

        for candidate in ("index.html", "robots.txt", "favicon.ico"):
            probe_url = f"{base_url}/{candidate}"
            probe = await self.helpers.request(probe_url)
            if getattr(probe, "status_code", 0) == 200:
                return (f"Open storage bucket (public object: {candidate})", tags)
        return ("", tags)
