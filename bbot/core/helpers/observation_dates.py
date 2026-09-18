"""Provider indexing dates, deliberately distinct from breach/incident dates."""

from datetime import datetime, timezone

INDEX_DATE_FIELDS = ("db_indexed_at", "indexed_at", "date_indexed", "indexed_date", "date")


def indexed_date(record):
    dates = []
    for field in INDEX_DATE_FIELDS:
        value = record.get(field)
        for item in value if isinstance(value, list) else [value]:
            if not isinstance(item, (str, int, float)) or isinstance(item, bool):
                continue
            try:
                if isinstance(item, (int, float)):
                    date = datetime.fromtimestamp(item / 1000 if item > 10**11 else item, timezone.utc)
                else:
                    date = datetime.fromisoformat(item.strip().replace("Z", "+00:00"))
                    if date.tzinfo is None:
                        date = date.replace(tzinfo=timezone.utc)
                date = date.astimezone(timezone.utc)
                if datetime(1970, 1, 1, tzinfo=timezone.utc) <= date <= datetime.now(timezone.utc):
                    dates.append(date)
            except (ValueError, OverflowError, OSError):
                continue
    return max(dates).isoformat().replace("+00:00", "Z") if dates else None


def indexed_date_tags(record):
    date = indexed_date(record)
    return [f"leak-indexed-at-{int(datetime.fromisoformat(date.replace('Z', '+00:00')).timestamp())}"] if date else []
