import asyncio
import base64
import json
import time
from types import SimpleNamespace

from bbot.modules.internal.excavate import excavate

SETTINGS = SimpleNamespace(description="", tags=[], emit_match=True)
DOTNET = "AAEAAAD/////AQAAAAAAAAAMAgAAAFJTeXN0ZW0uQ29sbGVjdGlvbnMuR2VuZXJpYy5MaXN0YDFbW1N5c3RlbS5TdHJpbmddXSwgU3lzdGVt"


def rule(rule_class):
    instance = object.__new__(rule_class)
    instance.excavate = SimpleNamespace(debug=lambda *args, **kwargs: None)
    if rule_class is excavate.FunctionalityExtractor:
        instance.file_upload_hosts = set()
    instance.reported = []

    async def report(event_data, event, yara_rule_settings, discovery_context, event_type="FINDING", **kwargs):
        instance.reported.append(event_data)

    instance.report = report
    return instance


def process(instance, yara_results, event):
    asyncio.run(instance.process(yara_results, event, SETTINGS, "context"))
    return instance.reported


def raw_text(path):
    return SimpleNamespace(type="RAW_TEXT", host="docs.example.com", parent=SimpleNamespace(data={"path": path}))


def http_response(host="app.example.com", headers=None):
    return SimpleNamespace(type="HTTP_RESPONSE", host=host, data={"header-dict": headers or {}})


def jwt(claims):
    def encode(value):
        return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")

    return f"{encode({'alg': 'HS256', 'typ': 'JWT'})}.{encode(claims)}.fixturesignature"


def test_serialized_object_needs_the_bytes_after_the_magic_to_form_an_object():
    serialized = {
        "Java": " rO0ABXQADUhlbGxvLCB3b3JsZCE=",
        "PHP_String": " czoyNDoiSGVsbG8sIHdvcmxkISBNb3JlIHRleHQuIjs=",
        "DOTNET": f" {DOTNET}",
        "Possible_Compressed": " H4sIAAAAAAAA/yu2MjS2UvJIzcnJ11Eozy/KSVFUsgYAZN5upRUAAAA=",
    }
    for identifier, match in serialized.items():
        assert len(process(rule(excavate.SerializationExtractor), {identifier: [match]}, http_response())) == 1

    lookalikes = {
        # Base64-looking runs in prose that match the prefix but decode to no object.
        "Java": " rO0ABQAAAAAA",
        "Ruby": " BAhzzzzzzzzz",
        "PHP_Object": " Tzo1abcdefgh",
        "Possible_Compressed": " H4sIAAAAzzzzzzzzzzzz",
    }
    for identifier, match in lookalikes.items():
        assert process(rule(excavate.SerializationExtractor), {identifier: [match]}, http_response()) == []


def test_serialized_objects_and_errors_quoted_in_documents_are_not_findings():
    for path in ("/tmp/3d-secure-guide.pdf", "/tmp/installation.md", "/tmp/handbook.docx"):
        assert process(rule(excavate.SerializationExtractor), {"DOTNET": [f" {DOTNET}"]}, raw_text(path)) == []
        assert process(rule(excavate.ErrorExtractor), {"PHP_3": ["Fatal error:"]}, raw_text(path)) == []

    # Logs and dumps are not documentation: an error or object in them is real.
    log = raw_text("/tmp/app-error.log")
    assert len(process(rule(excavate.SerializationExtractor), {"DOTNET": [f" {DOTNET}"]}, log)) == 1
    assert len(process(rule(excavate.ErrorExtractor), {"PHP_3": ["Fatal error:"]}, log)) == 1
    assert len(process(rule(excavate.ErrorExtractor), {"PHP_3": ["Fatal error:"]}, http_response())) == 1


def test_file_upload_is_reported_once_per_host_and_not_for_hosted_docs_widgets():
    upload = {"fileuploadfunc": ['<input type="file" name="avatar">']}
    extractor = rule(excavate.FunctionalityExtractor)

    process(extractor, upload, http_response("app.example.com"))
    process(extractor, upload, http_response("app.example.com"))
    process(extractor, upload, http_response("portal.example.com"))
    process(extractor, upload, http_response("docs.example.com", {"X-Mintlify-Client-Version": ["0.0.4074"]}))
    process(extractor, upload, http_response("docs2.example.com", {"x-gitbook-route-site": ["docs2.example.com/"]}))

    assert len(extractor.reported) == 2
    assert all("file upload functionality" in data["description"] for data in extractor.reported)


def test_supabase_anon_keys_and_per_visitor_jwts_are_not_findings():
    now = int(time.time())
    anon = jwt({"iss": "supabase", "ref": "fixture", "role": "anon", "iat": now, "exp": now + 10 * 365 * 86400})
    per_visitor = jwt({"sub": "visitor", "iat": now, "exp": now + 3600})
    service_role = jwt(
        {"iss": "supabase", "ref": "fixture", "role": "service_role", "iat": now, "exp": now + 10 * 365 * 86400}
    )
    week_long = jwt({"sub": "user", "iat": now, "exp": now + 7 * 86400})
    no_lifetime = jwt({"sub": "user"})

    reported = process(
        rule(excavate.JWTExtractor),
        {"jwt": [anon, per_visitor, service_role, week_long, no_lifetime]},
        http_response(),
    )

    assert [data["description"].rsplit("[", 1)[1].rstrip("]") for data in reported] == [
        service_role,
        week_long,
        no_lifetime,
    ]
