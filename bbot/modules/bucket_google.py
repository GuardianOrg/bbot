from bbot.modules.templates.bucket import bucket_template


class bucket_google(bucket_template):
    """
    Adapted from https://github.com/RhinoSecurityLabs/GCPBucketBrute/blob/master/gcpbucketbrute.py
    """

    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    meta = {
        "description": "Check for Google object storage related to target",
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

    cloudcheck_provider_name = "Google"
    delimiters = ("", "-", ".", "_")
    base_domains = ["storage.googleapis.com"]
    bad_permissions = [
        "storage.buckets.get",
        "storage.objects.get",
        "storage.objects.list",
    ]

    def filter_bucket(self, event):
        if not str(event.host).endswith(".googleapis.com"):
            return False, "bucket belongs to a different cloud provider"
        return True, ""

    def build_url(self, bucket_name, base_domain, region):
        return f"https://www.googleapis.com/storage/v1/b/{bucket_name}"

    async def check_bucket_open(self, bucket_name, url):
        bad_permissions = []
        try:
            list_permissions = "&".join(["=".join(("permissions", p)) for p in self.bad_permissions])
            url = f"https://www.googleapis.com/storage/v1/b/{bucket_name}/iam/testPermissions?" + list_permissions
            response = await self.helpers.request(url)
            permissions = response.json()
            if isinstance(permissions, dict):
                bad_permissions = list(permissions.get("permissions", {}))
        except Exception as e:
            self.info(f'Failed to enumerate permissions for bucket "{bucket_name}": {e}')
        msg = ""
        if bad_permissions:
            perms_str = ",".join(bad_permissions)
            msg = f"Open permissions on storage bucket ({perms_str})"
        return (msg, set())

    def check_bucket_exists(self, bucket_name, response):
        status_code = getattr(response, "status_code", 0)
        existent_bucket = status_code not in (0, 400, 404)
        return existent_bucket, set()
