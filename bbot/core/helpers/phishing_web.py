"""Bounded inspection of verified parking templates; DNS ownership alone cannot exclude a real website."""
import re

MAX_PAGE_BYTES = 65536

def classify_phishing_page(body):
    if len(body) >= MAX_PAGE_BYTES:
        return False, None  # A bounded prefix cannot prove there is no live login form later.
    text = body.decode('utf-8', errors='replace')
    # Provider parking templates are positive evidence of an inactive website;
    # registrar DNS/IPs alone are shared with real websites and cannot exclude it.
    credential_form = re.search(r'<input\b[^>]*(?:type\s*=\s*[\"\']?password\b|autocomplete\s*=\s*[\"\']?(?:current-password|one-time-code)\b)', text, re.I)
    godaddy = (re.search(r'window\.LANDER_SYSTEM\s*=\s*[\"\']PW[\"\']', text)
               and re.search(r'https://img1\.wsimg\.com/parking-lander/', text))
    hosting_kr = (re.search(r'id=[\"\']parking-wraps[\"\']', text)
                  and '/static/css/parking.css' in text
                  and re.search(r'href=[\"\']https?://(?:www\.)?hosting\.kr(?:/|[\"\'])', text))
    if not credential_form and (godaddy or hosting_kr):
        return True, None
    # Follow the minimal static bootstrap as a browser would, without executing JS.
    # The caller applies the same public-address, scope and hop limits as HTTP redirects.
    redirect = re.fullmatch(
        r'\s*(?:<!doctype\s+html>\s*)?<html>\s*<head>\s*<script>\s*'
        r'window\.onload\s*=\s*function\s*\(\s*\)\s*\{\s*window\.location\.href\s*=\s*'
        r'([\"\'])([^\"\'\r\n]+)\1\s*;?\s*\}\s*;?\s*</script>\s*</head>\s*</html>\s*', text, re.I)
    return False, redirect.group(2) if redirect else None

