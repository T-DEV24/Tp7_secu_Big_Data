try:
    from dotenv import load_dotenv
except ImportError:
    def load_dotenv():
        return False
load_dotenv()

from auth.mailer import send_otp_email

"""Application Flask web + API pour le TP MFA/RBAC/ABAC hospitalier."""
import csv
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

try:
    import bcrypt
except ImportError:
    bcrypt = None
try:
    import pandas as pd
except ImportError:
    pd = None
try:
    import pyotp
except ImportError:
    pyotp = None

from flask import (Flask, Response, flash, jsonify, redirect, render_template, request,
                   session, url_for)

from access.engine import authorize
from access.policy import DEPARTMENT_RESTRICTED_ROLES, MFA_REQUIRED_SENSITIVITIES, POLICY
from access.routes import access_bp
from auth.routes import auth_bp
from auth.security import (TOTP_INTERVAL_SECONDS, create_jwt, get_current_totp,
                           validate_password_policy, verify_password, verify_totp,
                           hash_password)
from security_hardening import configure_security, csrf, limiter
from db.connection import get_collection
from db.ensure_indexes import ensure_indexes
from audit.logger import log_access, log_account_event
from spark_jobs.risk_scoring import score_event
from audit.alert_writer import write_alert
from scripts.create_admin import ensure_admin_account
from analytics.aggregations import (get_alerts_by_action, get_alerts_by_day,
    get_alerts_by_department, get_alerts_by_hour, get_alerts_by_risk_level,
    get_dashboard_summary, get_high_risk_alerts, get_top_risky_users)
import re

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.secret_key = os.getenv("FLASK_SECRET_KEY", "dev-secret-change-me")

configure_security(app)
csrf.exempt(auth_bp)
app.register_blueprint(auth_bp)
app.register_blueprint(access_bp)

DATASETS = "datasets"
AUDIT_ROLES = {"admin_securite", "admin"}
ALERT_ROLES = AUDIT_ROLES


# ====================== INITIALISATION MONGODB ======================
def initialize_database():
    """Initialisation à exécuter à chaque démarrage (même avec gunicorn)"""
    print("=== Initialisation de la base MongoDB ===")
    try:
        _init_users()
        _init_resources()
        _init_logs()
        ensure_indexes()
    except Exception as exc:
        print(f"[INIT WARNING] MongoDB indisponible, mode CSV en lecture seule: {exc}")

    try:
        ensure_admin_account()
    except Exception as exc:
        print(f"[INIT WARNING] Impossible de créer/synchroniser le compte admin : {exc}")


# ====================== FONCTIONS EXISTANTES ======================
def _safe_find(collection_name, query=None, projection=None):
    try:
        return list(get_collection(collection_name).find(query or {}, projection or {"_id": 0}))
    except Exception:
        filename = {"users": "users.csv", "resources": "resources.csv", "access_logs": "access_logs.csv"}[collection_name]
        with open(os.path.join(DATASETS, filename), newline="", encoding="utf-8") as handle:
            return list(csv.DictReader(handle))


def _safe_find_one(collection_name, query):
    for item in _safe_find(collection_name):
        if all(str(item.get(k)) == str(v) for k, v in query.items()):
            return item
    return None


def _init_users():
    col = get_collection("users")
    if col.count_documents({}) > 0:
        print("[INIT] Collection 'users' déjà remplie — import ignoré.")
        return
    if pd is None or bcrypt is None or pyotp is None:
        raise RuntimeError("pandas, bcrypt and pyotp are required to initialize users")
    df = pd.read_csv(os.path.join(DATASETS, "users.csv"))
    docs = []
    for _, row in df.iterrows():
        docs.append({
            "user_id": row["user_id"], "name": row["name"], "role": row["role"],
            "department": row["department"],
            "mfa_enabled": str(row["mfa_enabled"]).lower() == "true",
            "clearance": row.get("clearance", "medical"),
            "password_hash": bcrypt.hashpw(str(row["user_id"]).encode(), bcrypt.gensalt()).decode(),
            "totp_secret": pyotp.random_base32(),
            "email": None,
            "account_activated": False,
        })
    col.insert_many(docs)
    print(f"[INIT] {len(docs)} utilisateurs importés dans 'users'.")


def _init_resources():
    col = get_collection("resources")
    if col.count_documents({}) > 0:
        print("[INIT] Collection 'resources' déjà remplie — import ignoré.")
        return
    if pd is None:
        raise RuntimeError("pandas is required to initialize resources")
    docs = pd.read_csv(os.path.join(DATASETS, "resources.csv")).to_dict(orient="records")
    col.insert_many(docs)
    print(f"[INIT] {len(docs)} ressources importées dans 'resources'.")


def _init_logs():
    col = get_collection("access_logs")
    if col.count_documents({}) > 0:
        print("[INIT] Collection 'access_logs' déjà remplie — import ignoré.")
        return
    if pd is None:
        raise RuntimeError("pandas is required to initialize logs")
    docs = pd.read_csv(os.path.join(DATASETS, "access_logs.csv")).to_dict(orient="records")
    col.insert_many(docs)
    print(f"[INIT] {len(docs)} entrées de log importées dans 'access_logs'.")


# ... (le reste du code reste IDENTIQUE : current_user, login_page, etc.)

# ====================== APPEL DE L'INITIALISATION ======================
initialize_database()

# ====================== ROUTES (le reste du fichier) ======================
# (Copie-colle tout le reste de ton code à partir de current_user() jusqu'à la fin)

if __name__ == "__main__":
    print("=== Démarrage du serveur Flask en mode local ===")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG", "true").lower() == "true")