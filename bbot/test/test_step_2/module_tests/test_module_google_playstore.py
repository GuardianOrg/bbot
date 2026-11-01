from .base import ModuleTestBase


class TestGoogle_Playstore(ModuleTestBase):
    modules_overrides = ["google_playstore", "speculate"]

    async def setup_after_prep(self, module_test):
        await module_test.mock_dns({"blacklanternsecurity.com": {"A": ["127.0.0.99"]}})
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/search?q=blacklanternsecurity&c=apps",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>"blacklanternsecurity" - Android Apps on Google Play</title>
            </head>
            <body>
            <a href="/store/apps/details?id=com.bbot.test&pcampaignid=dontmatchme&pli=1"/>
            <a href="/store/apps/details?id=com.bbot.other"/>
            <a href="/store/apps/details?id=com.lookalike.blacklanternsecurity"/>
            <a href="/store/apps/details?id=io.blacklanternsecurity.offline"/>
            <a href="/store/apps/details?id=com.unrelated.game"/>
            </body>
            </html>""",
        )
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/apps/details?id=com.bbot.test",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>BBOT</title>
            </head>
            <body>
            <meta name="appstore:developer_url" content="https://www.blacklanternsecurity.com">
            </div>
            </div>
            </body>
            </html>""",
        )
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/apps/details?id=com.bbot.other",
            text="""<!DOCTYPE html>
            <html>
            <head>
            <title>BBOT</title>
            </head>
            <body>
            <meta name="appstore:developer_url" content="">
            <a href="mailto:support@blacklanternsecurity.com"></a>
            </div>
            </div>
            </body>
            </html>""",
        )

        # Same package name, but the listing names someone else: optional only.
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/apps/details?id=com.lookalike.blacklanternsecurity",
            text="""<!DOCTYPE html>
            <html>
            <body>
            <meta name="appstore:developer_url" content="https://lookalike.example">
            <a href="mailto:support@lookalike.example"></a>
            </body>
            </html>""",
        )
        # Listing could not be read: a name match alone never makes it in scope.
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/apps/details?id=io.blacklanternsecurity.offline",
            status_code=404,
        )
        # Neither the name nor the listing ties it to the target: dropped.
        module_test.httpx_mock.add_response(
            url="https://play.google.com/store/apps/details?id=com.unrelated.game",
            text="""<html><body><a href="mailto:dev@unrelated.example"></a></body></html>""",
        )

    def check(self, module_test, events):
        optional = {e.data["id"]: e for e in events if e.type == "OPTIONAL_MOBILE_APP"}
        assert set(optional) == {"com.lookalike.blacklanternsecurity", "io.blacklanternsecurity.offline"}
        for app_id, e in optional.items():
            assert e.data["url"] == f"https://play.google.com/store/apps/details?id={app_id}"
            assert {"android", "optional"} <= set(e.tags)
            assert "blacklanternsecurity" in e.data["reason"]
        mobile = {e.data["id"] for e in events if e.type == "MOBILE_APP"}
        assert mobile == {"com.bbot.test", "com.bbot.other"}, "only listings naming the target are in-scope apps"
        assert not any(e.data.get("id") == "com.unrelated.game" for e in events if isinstance(e.data, dict))
        optional_ids = {e.id for e in optional.values()}
        assert not [e for e in events if e.parent_id in optional_ids], "no module may act on an optional app"
        assert len(events) == 8
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "DNS_NAME" and e.data == "blacklanternsecurity.com" and e.scope_distance == 0
            ]
        ), "Failed to emit target DNS_NAME"
        assert 1 == len(
            [e for e in events if e.type == "ORG_STUB" and e.data == "blacklanternsecurity" and e.scope_distance == 0]
        ), "Failed to find ORG_STUB"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "MOBILE_APP"
                and "android" in e.tags
                and e.data["id"] == "com.bbot.test"
                and e.data["url"] == "https://play.google.com/store/apps/details?id=com.bbot.test"
            ]
        ), "Failed to find bbot android app"
        assert 1 == len(
            [
                e
                for e in events
                if e.type == "MOBILE_APP"
                and "android" in e.tags
                and e.data["id"] == "com.bbot.other"
                and e.data["url"] == "https://play.google.com/store/apps/details?id=com.bbot.other"
            ]
        ), "Failed to find other bbot android app"
