from bbot.modules.base import BaseModule


class ip_geo_template(BaseModule):
    """
    Shared string/ASN normalization for IP geolocation API modules
    (ipwhois, ipquery, ...).
    """

    def clean_string(self, value):
        if isinstance(value, str) and value.strip():
            return value.strip()
        return None

    def clean_asn(self, value):
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            value = value.strip().upper()
            if value.startswith("AS"):
                value = value[2:]
            if value.isdigit():
                return int(value)
        return None
