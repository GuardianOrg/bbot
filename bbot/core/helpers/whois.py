from datetime import date, datetime


def whois_first_string(value):
    """Return the first non-empty stringified value, unwrapping lists/tuples/sets."""
    if isinstance(value, (list, tuple, set)):
        for item in value:
            text = whois_first_string(item)
            if text:
                return text
        return None
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def whois_to_iso(value):
    """Normalize a WHOIS date (datetime/date/list/str) to an ISO-8601 string."""
    if isinstance(value, (list, tuple, set)):
        for item in value:
            converted = whois_to_iso(item)
            if converted:
                return converted
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, date):
        return datetime.combine(value, datetime.min.time()).isoformat()
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


# The subset of WHOIS fields that identify the registrant/owner of a domain and
# only change when the domain is transferred to a different owner. Used to build a
# stable "ownership fingerprint" so downstream consumers can tell a re-registered /
# newly-purchased look-alike domain apart from one whose ownership is unchanged.
def normalize_whois_ownership(result):
    """Extract the ownership-fingerprint fields from a python-whois result dict.

    Deliberately excludes fields that legitimately change under the same owner
    (expiration_date, updated_date, status, dnssec, name servers).
    """
    if not isinstance(result, dict):
        result = {}
    return {
        "registrar": whois_first_string(result.get("registrar")),
        "registration_date": whois_to_iso(result.get("creation_date")),
        "registrant_org": whois_first_string(result.get("org")),
        "registrant_email": whois_first_string(result.get("emails")),
        "registrant_name": whois_first_string(result.get("name")),
        "registrant_country": whois_first_string(result.get("country")),
    }
