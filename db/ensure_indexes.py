"""Création centralisée des index MongoDB nécessaires au TP7.

Couvre toutes les collections utilisées par l'application, pas seulement
'alerts' : users, resources, access_logs, alerts, account_events.
"""
from pymongo import ASCENDING, DESCENDING
from db.connection import get_collection


def ensure_indexes() -> None:
    # --- users : identité, contrainte d'unicité forte ---
    users = get_collection("users")
    users.create_index("user_id", unique=True)
    # sparse=True : l'email est absent tant que le compte n'est pas activé.
    # unique=True : un email ne doit jamais être partagé par deux comptes,
    # sinon un OTP pourrait atterrir dans la mauvaise boîte mail.
    users.create_index("email", unique=True, sparse=True)
    users.create_index("role")
    users.create_index("department")
    users.create_index("account_activated")

    # --- resources : identité, requêtes de contrôle d'accès fréquentes ---
    resources = get_collection("resources")
    resources.create_index("resource_id", unique=True)
    resources.create_index("owner_department")
    resources.create_index("sensitivity")

    # --- access_logs : requêtes du dashboard/audit (par utilisateur, période) ---
    access_logs = get_collection("access_logs")
    access_logs.create_index("timestamp")
    access_logs.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)])
    access_logs.create_index("resource_id")
    access_logs.create_index("success")

    # --- alerts : déjà en place, complété ici pour rester la source unique ---
    alerts = get_collection("alerts")
    alerts.create_index("alert_id", unique=True, sparse=True)
    alerts.create_index("risk_score")
    alerts.create_index("timestamp")
    alerts.create_index([("user_id", ASCENDING), ("risk_score", DESCENDING)])
    alerts.create_index("risk_level")
    alerts.create_index("department")

    # --- account_events : traçabilité du cycle de vie des comptes ---
    account_events = get_collection("account_events")
    account_events.create_index([("user_id", ASCENDING), ("timestamp", DESCENDING)])
    account_events.create_index("event")
