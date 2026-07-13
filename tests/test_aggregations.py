from datetime import datetime, timedelta, timezone

import analytics.aggregations as agg


class FakeCollection:
    def __init__(self, docs):
        self.docs = docs

    def find(self, query=None, projection=None):
        query = query or {}
        docs = self.docs
        if "risk_score" in query:
            docs = [d for d in docs if d.get("risk_score", 0) >= query["risk_score"].get("$gte", 0)]
        return docs

    def aggregate(self, pipeline):
        grouped = {}
        for doc in self.docs:
            if doc.get("risk_score", 0) < 6:
                continue
            item = grouped.setdefault(doc["user_id"], {"_id": doc["user_id"], "total_score": 0, "alert_count": 0, "last_reason": doc.get("risk_reasons"), "dominant_risk_level": doc.get("risk_level")})
            item["total_score"] += doc.get("risk_score", 0)
            item["alert_count"] += 1
        return sorted(grouped.values(), key=lambda d: d["total_score"], reverse=True)[:10]


def test_aggregation_functions(monkeypatch):
    now = datetime.now(timezone.utc)
    docs = [
        {"timestamp": now, "user_id": "u1", "risk_score": 8, "risk_level": "élevé", "action": "read", "department": "cardio", "risk_reasons": ["mfa_non_valide"]},
        {"timestamp": now - timedelta(days=1), "user_id": "u2", "risk_score": 7, "risk_level": "moyen", "action": "write", "department": "radio", "risk_reasons": ["ip_externe"]},
    ]
    monkeypatch.setattr(agg, "get_collection", lambda name: FakeCollection(docs))
    assert len(agg.get_high_risk_alerts()) == 2
    assert agg.get_top_risky_users(1)[0]["user_id"] == "u1"
    assert agg.get_alerts_by_hour()[now.hour] >= 1
    assert agg.get_alerts_by_action()["read"] == 1
    assert agg.get_alerts_by_risk_level()["élevé"] == 1
    assert sum(agg.get_alerts_by_day(2).values()) >= 1
    assert agg.get_alerts_by_department()["cardio"] == 1
