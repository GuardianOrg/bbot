import importlib
import regex as re
from functools import cached_property
from bbot.modules.base import BaseModule


class bucket_template(BaseModule):
    watched_events = ["DNS_NAME", "STORAGE_BUCKET"]
    produced_events = ["STORAGE_BUCKET", "FINDING"]
    flags = ["active", "safe", "cloud-enum", "web-basic"]
    options = {
        "permutations": False,
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

    cloudcheck_provider_name = "Amazon|Google|DigitalOcean|etc"
    delimiters = ("", ".", "-")
    base_domains = ["s3.amazonaws.com|digitaloceanspaces.com|etc"]
    regions = [None]
    supports_open_check = True

    async def setup(self):
        self.buckets_tried = set()
        self.permutations = self.config.get("permutations", False)
        self.max_candidates = max(1, int(self.config.get("max_candidates", 32)))
        self.permutation_numbers = max(0, int(self.config.get("permutation_numbers", 2)))
        self.permutation_letters = bool(self.config.get("permutation_letters", False))
        self.expand_found_buckets = bool(self.config.get("expand_found_buckets", False))
        cloudcheck_import_path = "cloudcheck.providers"
        try:
            self.cloudcheck_provider = getattr(
                importlib.import_module(cloudcheck_import_path), self.cloudcheck_provider_name
            )
        except (ImportError, AttributeError) as e:
            return False, f"cloud helper at {cloudcheck_import_path} not found: {e}"
        return True

    async def filter_event(self, event):
        if event.type == "DNS_NAME" and event.scope_distance > 0:
            return False, "only accepts in-scope DNS_NAMEs"
        if event.type == "STORAGE_BUCKET":
            filter_result, reason = self.filter_bucket(event)
            if not filter_result:
                return (filter_result, reason)
        return True

    def filter_bucket(self, event):
        if not any(t.endswith(f"-{self.cloudcheck_provider_name.lower()}") for t in event.tags):
            return False, "bucket belongs to a different cloud provider"
        return True, ""

    async def handle_event(self, event):
        if event.type == "DNS_NAME":
            await self.handle_dns_name(event)
        elif event.type == "STORAGE_BUCKET":
            await self.handle_storage_bucket(event)

    async def handle_dns_name(self, event):
        buckets = set()
        base = self.helpers.unidecode(self.helpers.smart_decode_punycode(event.data))
        stem = self.helpers.domain_stem(base)
        for b in [base, stem]:
            split = b.split(".")
            for d in self.delimiters:
                bucket_name = d.join(split)
                buckets.add(bucket_name)
        async for bucket_name, url, tags, num_buckets in self.brute_buckets(buckets, permutations=self.permutations):
            await self.emit_storage_bucket(
                {"name": bucket_name, "url": url},
                "STORAGE_BUCKET",
                parent=event,
                tags=tags,
                context=f"{{module}} tried {num_buckets:,} bucket variations of {event.data} and found {{event.type}} at {url}",
            )

    async def handle_storage_bucket(self, event):
        url = event.data["url"]
        bucket_name = event.data["name"]
        if self.supports_open_check:
            description, tags = await self._check_bucket_open(bucket_name, url)
            if description:
                event_data = {"host": event.host, "url": url, "description": description}
                await self.emit_event(
                    event_data,
                    "FINDING",
                    parent=event,
                    tags=tags,
                    context=f"{{module}} scanned {event.type} and identified {{event.type}}: {description}",
                )

        if self.expand_found_buckets:
            async for bucket_name, new_url, tags, num_buckets in self.brute_buckets(
                [bucket_name], permutations=self.permutations, omit_base=True
            ):
                await self.emit_storage_bucket(
                    {"name": bucket_name, "url": new_url},
                    "STORAGE_BUCKET",
                    parent=event,
                    tags=tags,
                    context=f"{{module}} tried {num_buckets:,} variations of {url} and found {{event.type}} at {new_url}",
                )

    async def emit_storage_bucket(self, event_data, event_type, parent, tags, context):
        event_data["url"] = self.clean_bucket_url(event_data["url"])
        await self.emit_event(
            event_data,
            event_type,
            parent=parent,
            tags=tags,
            context=context,
        )

    async def brute_buckets(self, buckets, permutations=False, omit_base=False):
        bucket_list = list(dict.fromkeys(buckets))
        base_bucket_set = set(bucket_list)
        ordered_candidates = []
        seen_candidates = set()

        def add_candidate(candidate):
            if candidate in seen_candidates:
                return
            seen_candidates.add(candidate)
            ordered_candidates.append(candidate)

        for bucket_name in bucket_list:
            add_candidate(bucket_name)

        if permutations:
            for bucket_name in bucket_list:
                for mutation in self.helpers.word_cloud.mutations(
                    bucket_name,
                    devops=False,
                    cloud=False,
                    letters=self.permutation_letters,
                    numbers=self.permutation_numbers,
                ):
                    for delimiter in self.delimiters:
                        add_candidate(delimiter.join(mutation))

        filtered_candidates = []
        for candidate in ordered_candidates:
            if omit_base and candidate in base_bucket_set:
                continue
            if self.valid_bucket_name(candidate):
                filtered_candidates.append(candidate)
            if len(filtered_candidates) >= self.max_candidates:
                break

        num_buckets = len(filtered_candidates)
        bucket_urls_kwargs = []
        for base_domain in self.base_domains:
            for region in self.regions:
                for bucket_name in filtered_candidates:
                    url, kwargs = self.build_bucket_request(bucket_name, base_domain, region)
                    bucket_urls_kwargs.append((url, kwargs, (bucket_name, base_domain, region)))
        async for url, kwargs, (bucket_name, base_domain, region), response in self.helpers.request_custom_batch(
            bucket_urls_kwargs
        ):
            existent_bucket, tags = self._check_bucket_exists(bucket_name, response)
            if not existent_bucket:
                secondary_exists, secondary_tags = await self._check_bucket_exists_secondary(bucket_name, url, response)
                existent_bucket = existent_bucket or secondary_exists
                tags = set(tags).union(secondary_tags)
            if existent_bucket:
                yield bucket_name, url, tags, num_buckets

    def clean_bucket_url(self, url):
        # if needed, modify the bucket url before emitting it
        return url

    def build_bucket_request(self, bucket_name, base_domain, region):
        url = self.build_url(bucket_name, base_domain, region)
        return url, {}

    def _check_bucket_exists(self, bucket_name, response):
        self.debug(f'Checking if bucket exists: "{bucket_name}"')
        return self.check_bucket_exists(bucket_name, response)

    def check_bucket_exists(self, bucket_name, response):
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        existent_bucket = status_code != 404
        return (existent_bucket, tags)

    async def _check_bucket_open(self, bucket_name, url):
        self.debug(f'Checking if bucket is misconfigured: "{bucket_name}"')
        return await self.check_bucket_open(bucket_name, url)

    async def _check_bucket_exists_secondary(self, bucket_name, url, response):
        if hasattr(self, "check_bucket_exists_secondary"):
            return await self.check_bucket_exists_secondary(bucket_name, url, response)
        return False, set()

    async def check_bucket_open(self, bucket_name, url):
        response = await self.helpers.request(url)
        tags = self.gen_tags_exists(response)
        status_code = getattr(response, "status_code", 404)
        content = getattr(response, "text", "")
        open_bucket = status_code == 200 and "Contents" in content
        msg = ""
        if open_bucket:
            msg = "Open storage bucket"
        return (msg, tags)

    def valid_bucket_name(self, bucket_name):
        valid = self.is_valid_bucket_name(bucket_name)
        if valid and not self.helpers.is_ip(bucket_name):
            bucket_hash = hash(bucket_name)
            if bucket_hash not in self.buckets_tried:
                self.buckets_tried.add(bucket_hash)
                return True
        return False

    def is_valid_bucket_name(self, bucket_name):
        return any(regex.match(bucket_name) for regex in self.bucket_name_regexes)

    @cached_property
    def bucket_name_regexes(self):
        return [re.compile(regex) for regex in self.cloudcheck_provider.regexes["STORAGE_BUCKET_NAME"]]

    # @cached_property
    # def bucket_hostname_regexes(self):
    #     return [re.compile(regex) for regex in self.cloudcheck_provider.regexes["STORAGE_BUCKET_HOSTNAME"]]

    def build_url(self, bucket_name, base_domain, region):
        return f"https://{bucket_name}.{base_domain}/"

    def gen_tags_exists(self, response):
        return set()

    def gen_tags_open(self, response):
        return set()
