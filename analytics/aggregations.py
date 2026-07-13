"""Agrégations MongoDB partagées par le dashboard Flask et le notebook TP7."""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
from typing import Any



def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _parse_timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(text)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M UTC", "%Y-%m-%dT%H:%M:%S"):
            try:
                return datetime.strptime(str(value), fmt).replace(tzinfo=timezone.utc)
            except ValueError:
                continue
    return None


def _serialize(doc: dict) -> dict:
    doc = dict(doc)
    doc.pop("_id", None)
    if isinstance(doc.get("timestamp"), datetime):
        doc["timestamp"] = doc["timestamp"].astimezone(timezone.utc).isoformat()
    return doc


def _match_dates(min_score: int | None = None, date_from: datetime | None = None, date_to: datetime | None = None) -> dict:
    query: dict[str, Any] = {}
    if min_score is not None:
        query["risk_score"] = {"$gte": min_score}
    if date_from or date_to:
        query["timestamp"] = {}
        if date_from:
            query["timestamp"]["$gte"] = date_from
        if date_to:
            query["timestamp"]["$lte"] = date_to
    return query


def get_collection(name: str):
    from db.connection import get_collection as real_get_collection
    return real_get_collection(name)


def _all_alerts(query: dict | None = None) -> list[dict]:
    return [_serialize(doc) for doc in get_collection("alerts").find(query or {}, {"_id": 0})]


def get_high_risk_alerts(min_score: int = 6, date_from: datetime | None = None, date_to: datetime | None = None) -> list[dict]:
    alerts = _all_alerts(_match_dates(min_score, date_from, date_to))
    return sorted(alerts, key=lambda item: str(item.get("timestamp", "")), reverse=True)


def get_top_risky_users(n: int = 10) -> list[dict]:
    pipeline = [
        {"$match": {"risk_score": {"$gte": 6}}},
        {"$sort": {"timestamp": -1}},
        {"$group": {"_id": "$user_id", "total_score": {"$sum": "$risk_score"}, "alert_count": {"$sum": 1}, "last_reason": {"$first": "$risk_reasons"}, "dominant_risk_level": {"$first": "$risk_level"}}},
        {"$sort": {"total_score": -1, "alert_count": -1}},
        {"$limit": int(n)},
    ]
    rows = []
    for doc in get_collection("alerts").aggregate(pipeline):
        rows.append({
            "user_id": doc.get("_id", "inconnu"),
            "total_score": int(doc.get("total_score") or 0),
            "alert_count": int(doc.get("alert_count") or 0),
            "last_reason": ", ".join(doc.get("last_reason") or []) if isinstance(doc.get("last_reason"), list) else str(doc.get("last_reason") or ""),
            "dominant_risk_level": doc.get("dominant_risk_level") or "élevé",
        })
    return rows


def get_alerts_by_hour() -> dict[int, int]:
    counts = {hour: 0 for hour in range(24)}
    for alert in _all_alerts():
        dt = _parse_timestamp(alert.get("timestamp"))
        if dt:
            counts[dt.hour] += 1
    return counts


def _count_by(field: str) -> dict[str, int]:
    counter: Counter[str] = Counter()
    for alert in _all_alerts():
        counter[str(alert.get(field) or "inconnu")] += 1
    return dict(counter.most_common())


def get_alerts_by_action() -> dict[str, int]:
    return _count_by("action")


def get_alerts_by_risk_level() -> dict[str, int]:
    return _count_by("risk_level")


def get_alerts_by_day(last_n_days: int = 30) -> dict[str, int]:
    start = (_utc_now() - timedelta(days=last_n_days - 1)).date()
    counts = {(start + timedelta(days=i)).isoformat(): 0 for i in range(last_n_days)}
    for alert in _all_alerts():
        dt = _parse_timestamp(alert.get("timestamp"))
        if dt and dt.date().isoformat() in counts:
            counts[dt.date().isoformat()] += 1
    return counts


def get_alerts_by_department() -> dict[str, int]:
    return _count_by("department")


def get_dashboard_summary() -> dict[str, Any]:
    now = _utc_now()
    alerts = _all_alerts()
    dated = [(alert, _parse_timestamp(alert.get("timestamp"))) for alert in alerts]
    scores = [int(alert.get("risk_score") or 0) for alert in alerts]
    top = get_top_risky_users(1)
    return {
        "total_alerts": len(alerts),
        "alerts_24h": sum(1 for _, dt in dated if dt and dt >= now - timedelta(hours=24)),
        "alerts_7d": sum(1 for _, dt in dated if dt and dt >= now - timedelta(days=7)),
        "alerts_30d": sum(1 for _, dt in dated if dt and dt >= now - timedelta(days=30)),
        "average_score": round(sum(scores) / len(scores), 2) if scores else 0,
        "top_user": top[0] if top else None,
    }
