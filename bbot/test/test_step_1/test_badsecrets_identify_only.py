import asyncio
import base64
import json
from types import SimpleNamespace

import pytest

pytest.importorskip("badsecrets")

from bbot.modules.badsecrets import badsecrets, carve_all_modules_safely


def set_cookie_header(cookies):
    return {"set_cookie": ", ".join(f"{name}={value}; path=/" for name, value in cookies.items())}


def run(cookies, body=""):
    module = object.__new__(badsecrets)
    module.custom_secrets = None
    emitted = []

    async def run_in_executor_mp(function, **kwargs):
        return function(**kwargs)

    async def emit_event(data, event_type, parent, **kwargs):
        emitted.append((event_type, data))

    module.emit_event = emit_event
    module.scan = SimpleNamespace(
        helpers=SimpleNamespace(run_in_executor_mp=run_in_executor_mp, truncate_string=lambda s, n: s[:n])
    )
    event = SimpleNamespace(
        host="jobs.example.com",
        data={
            "url": "https://jobs.example.com/",
            "body": body,
            "header": set_cookie_header(cookies),
        },
    )
    asyncio.run(module.handle_event(event))
    return emitted


def test_unbroken_cookie_session_is_a_technology_not_a_finding():
    # A cookie-session cookie whose signature no known secret produces (seen on a job board).
    session = base64.b64encode(json.dumps({"flash": {}, "csrfSecret": "Zm9vYmFyYmF6"}).encode()).decode()
    cookies = {"session": session, "session.sig": "q3Vb7Zs5pR1l0gNd7cJ2kTbHw8E"}
    results, _ = carve_all_modules_safely(headers=set_cookie_header(cookies), url="https://jobs.example.com/")
    assert any(result["type"] == "IdentifyOnly" for result in results)

    emitted = run(cookies)

    assert emitted
    assert [event_type for event_type, _ in emitted] == ["TECHNOLOGY"] * len(emitted)
    assert {data["technology"] for _, data in emitted} == {"express.js signed cookie (cookie-session)"}


def test_a_known_cookie_session_secret_is_still_a_vulnerability():
    emitted = run({"foo": "eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==", "foo.sig": "zOQU7v7aTe_3zu7tnVuHi1MJ2DU"})

    assert [event_type for event_type, _ in emitted] == ["VULNERABILITY"]
    assert "Express.js Secret (cookie-session)" in emitted[0][1]["description"]
