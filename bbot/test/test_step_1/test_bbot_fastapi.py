import time
import httpx
from pathlib import Path
from subprocess import Popen
from contextlib import suppress

cwd = Path(__file__).parent.parent.parent


def test_bbot_fastapi():
    process = start_fastapi_server()

    try:

        # wait for the server to start with a timeout of 60 seconds
        start_time = time.time()
        while True:
            try:
                response = httpx.get("http://127.0.0.1:8978/ping")
                response.raise_for_status()
                break
            except httpx.HTTPError:
                if time.time() - start_time > 60:
                    raise TimeoutError("Server did not start within 60 seconds.")
                time.sleep(0.1)
                continue

        # run a scan
        response = httpx.get("http://127.0.0.1:8978/start", params={"targets": ["example.com"]})
        events = response.json()
        assert len(events) >= 3
        scan_events = [e for e in events if e["type"] == "SCAN"]
        assert len(scan_events) == 2

    finally:
        with suppress(Exception):
            process.terminate()


def start_fastapi_server():
    import os
    import sys

    env = os.environ.copy()
    with suppress(KeyError):
        del env["BBOT_TESTING"]
    python_executable = str(sys.executable)
    process = Popen(
        [python_executable, "-m", "uvicorn", "bbot.test.fastapi_test:app", "--port", "8978"], cwd=cwd, env=env
    )
    return process
