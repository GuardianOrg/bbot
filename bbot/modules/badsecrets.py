import multiprocessing
from pathlib import Path
from .base import BaseModule
from badsecrets.base import BadsecretsBase


def carve_all_modules_safely(**kwargs):
    results = []
    errors = []
    for module_class in BadsecretsBase.__subclasses__():
        try:
            module = module_class(custom_resource=kwargs.get("custom_resource", None))
            module_results = module.carve(**kwargs)
        except Exception as e:
            errors.append(f"{module_class.__name__}: {e}")
            continue

        for result in module_results or []:
            result["detecting_module"] = module_class.__name__
            results.append(result)

    return results, errors


class badsecrets(BaseModule):
    watched_events = ["HTTP_RESPONSE"]
    produced_events = ["FINDING", "VULNERABILITY", "TECHNOLOGY"]
    flags = ["active", "safe", "web-basic"]
    meta = {
        "description": "Library for detecting known or weak secrets across many web frameworks",
        "created_date": "2022-11-19",
        "author": "@liquidsec",
    }
    options = {"custom_secrets": None}
    options_desc = {
        "custom_secrets": "Include custom secrets loaded from a local file",
    }
    deps_pip = ["badsecrets~=0.13.47"]

    async def setup(self):
        self.custom_secrets = None
        custom_secrets = self.config.get("custom_secrets", None)
        if custom_secrets:
            secrets_path = Path(custom_secrets).expanduser()
            if secrets_path.is_file():
                self.custom_secrets = custom_secrets
                self.info(f"Successfully loaded secrets file [{custom_secrets}]")
            else:
                self.warning(f"custom secrets file [{custom_secrets}] is not valid")
                return False, "Custom secrets file not valid"
        return True

    @property
    def _module_threads(self):
        return max(1, multiprocessing.cpu_count() - 1)

    async def handle_event(self, event):
        resp_body = event.data.get("body", None)
        resp_headers = event.data.get("header", None)
        resp_cookies = {}
        if resp_headers:
            resp_cookies_raw = resp_headers.get("set_cookie", None)
            if resp_cookies_raw:
                if "," in resp_cookies_raw:
                    resp_cookies_list = resp_cookies_raw.split(",")
                else:
                    resp_cookies_list = [resp_cookies_raw]
                for c in resp_cookies_list:
                    c2 = c.lstrip(";").strip().split(";")[0].split("=")
                    if len(c2) == 2:
                        resp_cookies[c2[0]] = c2[1]
        if resp_body or resp_cookies:
            try:
                r_list, errors = await self.helpers.run_in_executor_mp(
                    carve_all_modules_safely,
                    body=resp_body,
                    headers=resp_headers,
                    cookies=resp_cookies,
                    url=event.data.get("url", None),
                    custom_resource=self.custom_secrets,
                )
            except Exception as e:
                self.warning(f"Error processing {event}: {e}")
                return
            for error in errors:
                self.debug(f"badsecrets detector failed for {event.data.get('url', None)}: {error}")
            if r_list:
                for r in r_list:
                    if r["type"] == "SecretFound":
                        data = {
                            "severity": r["description"]["severity"],
                            "description": (
                                f"A known {r['description']['secret']} secret was exposed for {r['description']['product']}. "
                                "If this value is accepted by the application or related infrastructure, it may allow authentication bypass, session forgery, data access, or impersonation depending on how the product uses the secret. "
                                "Secrets should be treated like passwords: once they are visible to an attacker, it is not enough to hide them again because they may already have been copied. "
                                "The affected value should be revoked or rotated, dependent sessions or tokens should be invalidated where possible, and logs should be reviewed for use of the exposed value. "
                                "The code or configuration path that exposed it should also be fixed so the replacement secret is not leaked again. "
                                f"Detected secret [{r['secret']}]; product [{self.helpers.truncate_string(r['product'], 2000)}]; details [{r['details']}]."
                            ),
                            "url": event.data["url"],
                            "host": str(event.host),
                        }
                        await self.emit_event(
                            data,
                            "VULNERABILITY",
                            event,
                            context=f'{{module}}\'s "{r["detecting_module"]}" module found known {r["description"]["product"]} secret ({{event.type}}): "{r["secret"]}"',
                        )
                    elif r["type"] == "IdentifyOnly":
                        # There is little value to presenting a non-vulnerable asp.net viewstate, as it is not crackable without a Matrioshka brain. Just emit a technology instead.
                        if r["detecting_module"] == "ASPNET_Viewstate":
                            technology = "microsoft asp.net"
                            await self.emit_event(
                                {"technology": technology, "url": event.data["url"], "host": str(event.host)},
                                "TECHNOLOGY",
                                event,
                                context=f"{{module}} identified {{event.type}}: {technology}",
                            )
                        else:
                            data = {
                                "description": (
                                    f"The response contains a recognizable {r['description']['product']} cryptographic artifact. "
                                    "This is not necessarily vulnerable by itself, but it identifies security-sensitive application state that should use strong keys, current algorithms, and product-specific hardening. "
                                    "For a non-specialist, this means the application is exposing data that appears to be protected, signed, encrypted, or otherwise security-related. "
                                    "That data may be safe when configured correctly, but weak keys, old algorithms, predictable values, or missing integrity checks can turn it into a bypass or tampering risk. "
                                    "Review the product-specific guidance, confirm the secret material is private, and avoid trusting client-controlled values without server-side validation. "
                                    f"Observed product [{self.helpers.truncate_string(r['product'], 2000)}]."
                                ),
                                "url": event.data["url"],
                                "host": str(event.host),
                            }
                            await self.emit_event(
                                data,
                                "FINDING",
                                event,
                                context=f'{{module}} identified cryptographic product ({{event.type}}): "{r["description"]["product"]}"',
                            )
