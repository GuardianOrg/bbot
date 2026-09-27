from bbot.core.helpers.whois import normalize_whois_ownership, whois_result_with_registrant


class WhoisResult(dict):
    text = """Registrar Abuse Contact Email: domainabuse@cscglobal.com
Registrant Name: Domain Admin
Registrant Organization: Trends International, LLC
Registrant Email: registrar@art.com
Admin Email: registrar@art.com
Tech Email: dns-admin@cscglobal.com
"""


def test_registrant_fingerprint_uses_role_specific_whois_fields():
    result = WhoisResult(
        registrar="CSC Corporate Domains (Canada) Company",
        creation_date="2000-10-16T14:55:47Z",
        registrant_name="Domain Admin",
        emails=["domainabuse@cscglobal.com", "registrar@art.com", "dns-admin@cscglobal.com"],
    )

    fingerprint = normalize_whois_ownership(whois_result_with_registrant(result))

    assert fingerprint["registrant_email"] == "registrar@art.com"
    assert fingerprint["registrant_name"] == "Domain Admin"
    assert fingerprint["registrant_org"] == "Trends International, LLC"
    assert fingerprint["registration_date"] == "2000-10-16T14:55:47Z"


def test_unattributed_email_list_is_not_treated_as_registrant():
    result = {"emails": ["abuse@namespro.ca", "info@masermedia.com"]}

    assert normalize_whois_ownership(result)["registrant_email"] is None
