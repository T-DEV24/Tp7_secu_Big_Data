"""Création centralisée des index MongoDB nécessaires au TP7.

Couvre toutes les collections utilisées par l'application, pas seulement
'alerts' : users, resources, access_logs, alerts, account_events.
"""
from pymongo import ASCENDING, DESCENDING
from db.connection import get_collection


def _safe_create_index(collection, keys, **kwargs):
    """Isole chaque création d'index : un échec ne bloque pas les suivants."""
    try:
        collection.create_index(keys, **kwargs)
    except Exception as e:
        print(f"[INDEX WARNING] {collection.name} / {keys} : {e}")


def ensure_indexes() -> None:
    # --- users : identité, contrainte d'unicité forte ---
    users = get_collection("users")
    _safe_create_index(users, "user_id", unique=True)
    # Partial index (pas sparse) : n'indexe que les documents où email est
    # une vraie chaîne. Contrairement à sparse=True, ça exclut aussi les
    # documents où email existe mais vaut null — cas réel dans nos données
    # (comptes non activés stockés avec email: null plutôt qu'absent).
    _safe_create_index(
        users, "email", unique=True,
        partialFilterExpression={"email": {"$type": "string"}},
    )
    _safe_create_index(users, "role")
    _safe_create_index(users, "department")
    _safe_create_index(users, "account_activated")

    # --- resources : identité, requêtes de contrôle d'accès fréquentes ---
    resources = get_collection("resources")
    _safe_create_index(resources, "resource_id", unique=True)
    _safe_create_index(resources, "owner_department")
    _safe_create_index(resources, "sensitivity")

    # --- access_logs : requêtes du dashboard/audit (par utilisateur, période) ---
    access_logs = get_collection("access_logs")
    _safe_create_index(access_logs, "timestamp")
    _safe_create_index(access_logs, [("user_id", ASCENDING), ("timestamp", DESCENDING)])
    _safe_create_index(access_logs, "resource_id")
    _safe_create_index(access_logs, "success")

    # --- alerts : déjà en place, complété ici pour rester la source unique ---
    alerts = get_collection("alerts")
    _safe_create_index(alerts, "alert_id", unique=True, sparse=True)
    _safe_create_index(alerts, "risk_score")
    _safe_create_index(alerts, "timestamp")
    _safe_create_index(alerts, [("user_id", ASCENDING), ("risk_score", DESCENDING)])
    _safe_create_index(alerts, "risk_level")
    _safe_create_index(alerts, "department")

    # --- account_events : traçabilité du cycle de vie des comptes ---
    account_events = get_collection("account_events")
    _safe_create_index(account_events, [("user_id", ASCENDING), ("timestamp", DESCENDING)])
    _safe_create_index(account_events, "event")
