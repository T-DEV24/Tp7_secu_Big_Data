"""
audit/logger.py
Fonction unique d'écriture dans access_logs.
Appelée systématiquement par le moteur de décision (autorisé OU refusé).
Un refus non journalisé = une tentative d'intrusion invisible.
"""
from db.connection import get_collection
from db.models import make_log

def log_access(user_id: str, role: str, department: str,
               resource_id: str, resource_type: str, sensitivity: str,
               action: str, ip: str, success: bool,
               mfa_passed: bool, reason: str) -> None:
    """
    Insère une entrée dans la collection access_logs.
    Champs garantis : timestamp, user_id, role, department,
                      resource_id, resource_type, sensitivity,
                      action, ip, success, mfa_passed, reason.
    """
    entry = make_log(
        user_id=user_id,
        role=role,
        department=department,
        resource_id=resource_id,
        resource_type=resource_type,
        sensitivity=sensitivity,
        action=action,
        ip=ip,
        success=success,
        mfa_passed=mfa_passed,
        reason=reason,
    )
    try:
        get_collection("access_logs").insert_one(entry)
    except Exception as exc:
        # En dernier recours : ne jamais laisser une erreur DB
        # bloquer l'application, mais le signaler clairement.
        print(f"[AUDIT ERROR] Impossible d'écrire dans access_logs : {exc}")


def log_account_event(user_id: str, event: str, ip: str) -> None:
    """
    Trace les événements liés au cycle de vie du compte (ex. account_activated,
    password_changed). Écrit dans une collection dédiée account_events, séparée
    de access_logs qui ne concerne que les accès aux ressources.
    """
    from datetime import datetime, timezone
    entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "user_id":   user_id,
        "event":     event,
        "ip":        ip,
    }
    try:
        get_collection("account_events").insert_one(entry)
    except Exception as exc:
        print(f"[AUDIT ERROR] Impossible d'écrire dans account_events : {exc} — événement : {entry}")