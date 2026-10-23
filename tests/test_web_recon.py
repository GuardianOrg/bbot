import json
import asyncio

from bbot.web_recon import batches, merge_observations, normalize_url, observation, select_urls, choose_whatweb
from bbot.modules.web_recon import web_recon


ORIGIN = "https://www.example.com"


def test_exact_origin_depth_query_and_dynamic_deduplication():
    assert normalize_url("https://www.example.com:443/a?token=secret&b=2#x", ORIGIN) == (
        "https://www.example.com/a?b=&token=", "/")
    assert normalize_url("http://www.example.com/a", ORIGIN) is None
    assert normalize_url("https://www.example.com.evil.test/a", ORIGIN) is None
    assert normalize_url(ORIGIN + "/" + "/".join(str(i) for i in range(11)), ORIGIN) is None
    records = [observation(ORIGIN + "/users/123456/profile", ORIGIN, "katana", status=200, live=True),
               observation(ORIGIN + "/users/654321/profile", ORIGIN, "waymore")]
    merged, counts = merge_observations(records, ORIGIN)
    assert len(merged) == 1
    assert merged[0]["sources"] == ["katana", "waymore"]
    assert counts["duplicates"] == 1


def test_diverse_selection_stays_bounded_on_large_site():
    records = [observation(f"{ORIGIN}/f{folder}/item{index}", ORIGIN, "waymore")
               for folder in range(30) for index in range(50)]
    selected = select_urls(records)
    assert len(selected) == 200
    folders = {}
    for record in selected:
        folders[record["folder"]] = folders.get(record["folder"], 0) + 1
    assert len(folders) == 30
    assert max(folders.values()) <= 10


def test_whatweb_uses_only_live_distinct_html_and_20_global():
    records = []
    for folder in range(30):
        for index in range(3):
            record = observation(f"{ORIGIN}/f{folder}/p{index}", ORIGIN, "katana", status=200,
                                 content_type="text/html", body_hash=f"{folder * 3 + index:064x}", live=True)
            records.append(record)
    records.append(observation(f"{ORIGIN}/archived", ORIGIN, "waymore", content_type="text/html",
                               body_hash="f" * 64))
    picked = choose_whatweb(records)
    assert len(picked) == 20
    assert len({record["folder"] for record in picked}) == 20
    assert all(record["live"] for record in picked)


def test_batch_bytes_stay_below_naxus_compaction_threshold():
    records = [observation(f"{ORIGIN}/f{i}/" + "x" * 200, ORIGIN, "katana", status=200, live=True)
               for i in range(200)]
    chunks = list(batches(ORIGIN, records, {"selected": 200}))
    assert sum(len(chunk["urls"]) for chunk in chunks) == 200
    assert len(chunks) < 200
    assert all(len(json.dumps(chunk, separators=(",", ":")).encode()) < 16_384 for chunk in chunks)


def test_katana_response_is_reused_and_waymore_is_historical(tmp_path):
    katana = tmp_path / "katana.jsonl"
    katana.write_text(json.dumps({"request": {"endpoint": ORIGIN + "/api/users/12345"},
                                  "response": {"status_code": 401, "headers": {"Content-Type": "text/html"},
                                               "body": "<html>login</html>", "content_length": 18}}) + "\n")
    waymore = tmp_path / "waymore.txt"
    waymore.write_text(ORIGIN + "/old\nhttps://outside.example/secret\n")
    module = object.__new__(web_recon)
    packets = {}
    current = module._katana_records(katana, ORIGIN)
    module._katana_packets(katana, ORIGIN, {current[0]["url"]}, packets)
    historical = module._waymore_records(waymore, ORIGIN)
    assert current[0]["live"] is True
    assert current[0]["status_code"] == 401
    assert current[0]["body_length"] == 18
    assert current[0]["url"] in packets
    assert historical == [{"url": ORIGIN + "/old", "folder": "/", "sources": ["waymore"], "live": False}]


def test_httpx_body_and_raw_header_are_saved_for_offline_whatweb(tmp_path):
    module = object.__new__(web_recon)
    module.httpx = "httpx"
    module.scan = type("Scan", (), {"custom_http_headers": {}})()

    async def write_httpx_output(_command, _timeout):
        (tmp_path / "httpx.jsonl").write_text(json.dumps({
            "url": ORIGIN + "/login", "status_code": 200, "content_length": 17,
            "content_type": "text/html", "raw_header": "HTTP/1.1 200 OK\r\nServer: nginx\r\n",
            "body": "<html>Hi</html>",
        }) + "\n")
        return "ok"

    module._run = write_httpx_output
    record = observation(ORIGIN + "/login", ORIGIN, "waymore")
    packets = {}
    asyncio.run(module._probe_missing([record], tmp_path, ORIGIN, packets))
    assert record["live"] is True
    assert len(record["body_sha256"]) == 64
    assert "Server: nginx" in packets[record["url"]].read_text()
