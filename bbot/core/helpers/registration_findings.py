"""Registration risks that can be verified in the initial scan, without a previous observation."""
import math
import re
from datetime import datetime, timezone

NON_EPP_REGISTRIES = {'ch', 'li', 'de', 'eu'}
EPP_STATUS_EVIDENCE = {'ok', 'active', 'inactive', 'pendingcreate', 'pendingdelete', 'pendingrenew',
                       'pendingrestore', 'pendingtransfer', 'pendingupdate', 'redemptionperiod',
                       'addperiod', 'autorenewperiod', 'renewperiod', 'transferperiod'}


def lock_statuses_published(host, statuses):
    tokens = [re.sub(r'[^a-z]', '', str(value).split(' http')[0].lower()) for value in (statuses or [])]
    visible = any(value in EPP_STATUS_EVIDENCE or value.startswith(('client', 'server')) for value in tokens)
    return visible and (host.rsplit('.', 1)[-1].lower() not in NON_EPP_REGISTRIES
                            or any(value.startswith(('client', 'server')) for value in tokens))


def initial_registration_findings(data, *, now=None):
    host = str(data.get('host') or '').lower().rstrip('.')
    if not host:
        return []
    raw = data.get('whois_status') or []
    statuses = {re.sub(r'[^a-z]', '', str(value).split(' http')[0].lower()) for value in raw}
    now = now or datetime.now(timezone.utc)
    risks = []
    dangerous = statuses & {'clienthold', 'serverhold', 'inactive', 'pendingdelete', 'redemptionperiod', 'pendingtransfer', 'pendingupdate'}
    if dangerous:
        critical = bool(dangerous & {'pendingdelete', 'redemptionperiod'})
        risks.append(('lifecycle:critical' if critical else 'lifecycle:high', 'CRITICAL' if critical else 'HIGH',
                      f'Dangerous domain lifecycle status detected for {host}'))
    visible = data.get('lock_statuses_published') is not False and lock_statuses_published(host, raw)
    transfer = bool(statuses & {'clienttransferprohibited', 'servertransferprohibited'})
    if visible and not transfer:
        risks.append(('lock:missing', 'HIGH', f'Domain transfer lock is not visible for {host}'))
    elif visible and not (statuses & {'clientdeleteprohibited', 'serverdeleteprohibited'} and statuses & {'clientupdateprohibited', 'serverupdateprohibited'}):
        risks.append(('lock:optional', 'LOW', f'Domain registry protection locks are incomplete for {host}'))
    expiration = data.get('expiration_date')
    if expiration:
        try:
            date = datetime.fromisoformat(str(expiration).replace('Z', '+00:00'))
            if date.tzinfo is None:
                date = date.replace(tzinfo=timezone.utc)
            days = math.ceil((date - now).total_seconds() / 86400)
            if days <= 30:
                window = 0 if days <= 0 else 7 if days <= 7 else 30
                title = f'Domain registration has expired: {host}' if window == 0 else f'Domain registration expires soon: {host}'
                risks.append((f'expiry:{window}', 'CRITICAL' if window <= 7 else 'HIGH', title))
        except (TypeError, ValueError):
            pass  # An unavailable date says nothing about expiry; other verified risks remain reportable.
    return [{'host': host, 'title': title, 'severity': severity, 'category': 'WHOIS',
             'dedupe_key': f'whois-initial:{value}:{host}', 'monitor_finding_type': 'rdap_registration_change',
             'monitor_value': value, 'evidence': {'whois_status': raw, 'expiration_date': expiration},
             'description': f'{title}. The original registration lookup published these statuses: {sorted(statuses)}. '
                            f'The published expiration date is {expiration or "unavailable"}. This is an initial registration observation, not proof of an ownership transition.',
             'recommendation': 'Confirm the published state with the registrar; renew the registration and enable supported protections as appropriate.'}
            for value, severity, title in risks]
