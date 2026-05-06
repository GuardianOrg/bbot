from bbot.modules.templates.bucket import bucket_template


class bucket_firebase(bucket_template):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    meta = {
        "description": "Check for open Firebase databases related to target",
        "created_date": "2023-03-20",
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

    cloudcheck_provider_name = "Google"
    delimiters = ("", "-")
    base_domains = ["firebaseio.com"]

    def filter_bucket(self, event):
        host = str(event.host)
        if not any(host.endswith(f".{d}") for d in self.base_domains):
            return False, "bucket belongs to a different cloud provider"
        return True, ""

    def build_url(self, bucket_name, base_domain, region):
        return f"https://{bucket_name}.{base_domain}/.json"

    def check_bucket_exists(self, bucket_name, response):
        status_code = getattr(response, "status_code", 404)
        # For Firebase this module is most useful for publicly readable databases.
        # Private 401 responses are too noisy and frequently unrelated to the target stem.
        return status_code == 200, set()

    async def check_bucket_open(self, bucket_name, url):
        probe_url = url if str(url).rstrip("/").endswith(".json") else f"{str(url).rstrip('/')}/.json"
        response = await self.helpers.request(probe_url)
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        msg = ""
        if status_code == 200:
            msg = "Open storage bucket"
            return msg, tags, {"permissions": ["read"]}
        return (msg, tags, {})
