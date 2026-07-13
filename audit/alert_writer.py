"""
audit/alert_writer.py
Écriture minimisée des alertes TP7.

Seuls les champs nécessaires à la supervision sont conservés. Aucun champ issu
de patients_sensibles.csv ne doit être écrit par ce module.
"""
import csv
import os
from uuid import uuid4

from db.connection import get_collection

ALERT_FIELDS = [
    "timestamp", "user_id", "role", "department", "resource_id", "resource_type",
    "sensitivity", "action", "ip", "success", "mfa_passed", "risk_score",
    "risk_level", "risk_reasons", "alert_id",
]


def _minimal_alert(scored_event: dict) -> dict:
    """Construit un document d'alerte limité aux champs autorisés."""
    alert = {field: scored_event.get(field, "") for field in ALERT_FIELDS if field != "alert_id"}
    alert["alert_id"] = str(uuid4())
    return alert


def _write_alert_fallback(alert: dict) -> None:
    """Écrit l'alerte dans un CSV de secours si MongoDB est indisponible."""
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", "alerts_fallback.csv")
    exists = os.path.exists(path)
    row = dict(alert)
    row["risk_reasons"] = " | ".join(row.get("risk_reasons") or [])
    with open(path, "a", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=ALERT_FIELDS)
        if not exists:
            writer.writeheader()
        writer.writerow(row)


def write_alert(scored_event: dict) -> None:
    """Écrit une alerte uniquement si le seuil fixe risk_score >= 6 est atteint."""
    if int(scored_event.get("risk_score", 0) or 0) < 6:
        return
    alert = _minimal_alert(scored_event)
    try:
        get_collection("alerts").insert_one(alert)
    except Exception as exc:
        try:
            _write_alert_fallback(alert)
            print(f"[ALERTES] MongoDB indisponible, alerte écrite en CSV : {exc}")
        except Exception as fallback_exc:
            print(f"[ALERTES] Impossible d'écrire l'alerte : {fallback_exc}")


def write_alerts_bulk(scored_events: list) -> int:
    """Écrit les alertes élevées et retourne leur nombre."""
    count = 0
    for event in scored_events:
        if int(event.get("risk_score", 0) or 0) >= 6:
            write_alert(event)
            count += 1
    return count
