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
# Rôles autorisés à voir le dashboard de supervision des alertes ET le
# journal d'accès (access_log) — auparavant ces pages étaient accessibles
# à n'importe quel utilisateur connecté, quel que soit son rôle.
AUDIT_ROLES = {"admin_securite", "admin"}
ALERT_ROLES = AUDIT_ROLES


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
            # Compte non activé : le mot de passe par défaut (= user_id) reste
            # valide jusqu'à ce que l'utilisateur passe par /activate-account.
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


def current_user():
    uid = session.get("user_id")
    return _safe_find_one("users", {"user_id": uid}) if uid else None


LOCK_THRESHOLD = 5
LOCK_DURATION = timedelta(minutes=5)


def _utcnow():
    return datetime.now(timezone.utc)


def _parse_datetime(value):
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def _is_account_locked(user):
    locked_until = _parse_datetime(user.get("locked_until"))
    return bool(locked_until and locked_until > _utcnow())


def _record_failed_login(user):
    attempts = int(user.get("failed_attempts") or 0) + 1
    update = {"failed_attempts": attempts}
    if attempts >= LOCK_THRESHOLD:
        update["locked_until"] = _utcnow() + LOCK_DURATION
    try:
        get_collection("users").update_one({"user_id": user["user_id"]}, {"$set": update})
    except Exception:
        user.update(update)
    return update


def _clear_login_failures(user):
    try:
        get_collection("users").update_one(
            {"user_id": user["user_id"]},
            {"$set": {"failed_attempts": 0}, "$unset": {"locked_until": ""}},
        )
    except Exception:
        user["failed_attempts"] = 0
        user.pop("locked_until", None)


def _mfa_enabled(user):
    return str(user.get("mfa_enabled")).lower() == "true"


def _has_known_role(user):
    return user.get("role") in POLICY


def _get_totp_secret(user):
    if user.get("totp_secret"):
        return user["totp_secret"]
    return session.get("pending_totp_secret")


def _record_login_event(user_id, role, department, success, mfa_passed, reason):
    """Journalise une tentative de connexion dans access_logs ET déclenche
    immédiatement le scoring de risque.

    Avant ce correctif, les tentatives de connexion (échecs, hors plage
    horaire...) n'étaient JAMAIS écrites dans access_logs : seule la lecture/
    écriture de ressources via /access/... l'était. Et même journalisées,
    la génération d'alertes dépendait d'un job batch séparé (Kafka/Spark ou
    le notebook), jamais déclenché automatiquement par l'app web. Résultat :
    se tromper de mot de passe ou se connecter hors 6h-20h ne produisait
    jamais d'alerte dans le dashboard. On journalise ET on score en direct.
    """
    ip = request.remote_addr or "0.0.0.0"
    now = _utcnow()
    log_access(
        user_id=user_id, role=role, department=department,
        resource_id="login", resource_type="authentification",
        sensitivity="interne", action="login", ip=ip,
        success=success, mfa_passed=mfa_passed, reason=reason,
    )
    try:
        scored = score_event({
            "user_id": user_id, "role": role, "department": department,
            "resource_id": "login", "resource_type": "authentification",
            "sensitivity": "interne", "action": "login", "ip": ip,
            "success": success, "mfa_passed": mfa_passed,
            "hour": now.hour, "timestamp": now.isoformat(),
        })
        write_alert(scored)
    except Exception as exc:
        print(f"[ALERTES] Scoring temps réel impossible pour {user_id} : {exc}")


def _prepare_mfa_challenge(user):
    if pyotp is None:
        raise RuntimeError("pyotp is required to prepare MFA challenges")
    secret = user.get("totp_secret") or pyotp.random_base32()
    session["pending_totp_secret"] = secret
    code = get_current_totp(secret)
    minutes = TOTP_INTERVAL_SECONDS // 60
    if not send_otp_email(user["user_id"], code, minutes, recipient_email=user.get("email")):
        print(f"[MFA] Code OTP pour {user['user_id']} : {code} (expire dans {minutes} minutes)")


def _resource_access_preview(user, resource):
    if resource.get("type") not in POLICY.get(user.get("role"), {}).get("read", []):
        return "Refusé par rôle"
    if user.get("role") in DEPARTMENT_RESTRICTED_ROLES and user.get("department") != resource.get("owner_department"):
        return "Refusé par département"
    if resource.get("sensitivity") in MFA_REQUIRED_SENSITIVITIES and not session.get("mfa_ok", False):
        return "MFA requis"
    return "Lecture possible"


@app.context_processor
def inject_user():
    user = current_user()
    return {
        "current_user": user,
        "session_started": session.get("login_time"),
        "alert_roles": ALERT_ROLES,
        "audit_roles": AUDIT_ROLES,
    }


def role_required(*roles, redirect_endpoint="resources_page"):
    """redirect_endpoint doit être une page accessible à TOUS les rôles
    connus, jamais la page protégée elle-même (sinon boucle de redirection)."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                flash("Veuillez vous connecter pour continuer.", "warning")
                return redirect(url_for("login_page"))
            if user.get("role") not in roles:
                flash("Accès refusé pour ce rôle.", "danger")
                return redirect(url_for(redirect_endpoint))
            return view(*args, **kwargs)
        return wrapped
    return decorator


def api_role_required(*roles):
    """Comme role_required, mais renvoie une erreur JSON 403 au lieu d'une
    redirection — adapté aux endpoints /api/... et aux exports CSV appelés
    en AJAX/téléchargement plutôt que navigués en HTML."""
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return jsonify({"error": "Non authentifié"}), 401
            if user.get("role") not in roles:
                return jsonify({"error": "Accès refusé pour ce rôle."}), 403
            return view(*args, **kwargs)
        return wrapped
    return decorator


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Veuillez vous connecter pour continuer.", "warning")
            return redirect(url_for("login_page"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login_page"))


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per 5 minutes", methods=["POST"])
def login_page():
    if request.method == "POST":
        user_id = request.form.get("user_id", "").strip()
        password = request.form.get("password", "")
        user = _safe_find_one("users", {"user_id": user_id})
        if user and _is_account_locked(user):
            _record_login_event(user_id, user.get("role", "?"), user.get("department", "?"),
                                 success=False, mfa_passed=False, reason="Compte verrouillé (trop d'échecs)")
            flash(f"Compte temporairement verrouillé après trop d'échecs. Réessayez dans {int(LOCK_DURATION.total_seconds() // 60)} minutes.", "danger")
            return render_template("login.html"), 423
        # Le mot de passe par défaut (= user_id) n'est un raccourci valide QUE
        # tant que le compte n'a pas été activé. Une fois account_activated=True,
        # seul le hash bcrypt du mot de passe choisi par l'utilisateur compte —
        # sinon n'importe qui connaissant l'identifiant pourrait se connecter.
        is_activated = bool(user and user.get("account_activated", False))
        default_password_allowed = bool(user and not is_activated and password == user_id)
        password_ok = bool(user and (
            (user.get("password_hash") and verify_password(password, user["password_hash"]))
            or default_password_allowed
        ))
        if not password_ok:
            if user:
                _record_failed_login(user)
                _record_login_event(user_id, user.get("role", "?"), user.get("department", "?"),
                                     success=False, mfa_passed=False, reason="Mot de passe invalide")
            else:
                _record_login_event(user_id, "inconnu", "inconnu",
                                     success=False, mfa_passed=False, reason="Identifiant utilisateur inconnu")
            flash("Identifiants invalides.", "danger")
            return render_template("login.html")
        _clear_login_failures(user)
        if not _has_known_role(user):
            flash("Rôle non autorisé pour cette application.", "danger")
            return render_template("login.html")
        session.clear()
        if not user.get("account_activated", False):
            # Première connexion : mot de passe par défaut accepté (= user_id),
            # mais aucune session complète n'est ouverte tant que le compte
            # n'a pas été activé (nouveau mot de passe + email validés).
            session["pending_activation_user_id"] = user_id
            flash("Première connexion : veuillez définir un nouveau mot de passe et votre email.", "info")
            return redirect(url_for("activate_account_page"))
        session["pending_user_id"] = user_id
        if _mfa_enabled(user):
            _prepare_mfa_challenge(user)
            _record_login_event(user_id, user.get("role", "?"), user.get("department", "?"),
                                 success=True, mfa_passed=False, reason="Mot de passe validé, OTP en attente")
            flash(f"Code OTP envoyé dans le terminal. Il expire dans {TOTP_INTERVAL_SECONDS // 60} minutes.", "info")
            return redirect(url_for("verify_otp_page"))
        _record_login_event(user_id, user.get("role", "?"), user.get("department", "?"),
                             success=True, mfa_passed=False, reason="Connexion réussie (MFA désactivé)")
        _open_session(user, mfa_ok=False)
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/activate-account", methods=["GET", "POST"])
@limiter.limit("5 per 5 minutes", methods=["POST"])
def activate_account_page():
    """
    Formulaire de première connexion : affiché uniquement juste après un login
    réussi avec le mot de passe par défaut (= user_id) sur un compte non activé.
    Demande un nouveau mot de passe + un email valide, les enregistre (mot de
    passe haché, email en clair pour recevoir l'OTP), puis enchaîne sur le MFA.
    """
    user_id = session.get("pending_activation_user_id")
    user = _safe_find_one("users", {"user_id": user_id}) if user_id else None
    if not user:
        flash("Veuillez vous reconnecter pour continuer.", "warning")
        return redirect(url_for("login_page"))
    if user.get("account_activated", False):
        # Le compte a déjà été activé entre-temps : on ne repasse pas par ici.
        return redirect(url_for("login_page"))

    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip().lower()
        confirm_email = request.form.get("confirm_email", "").strip().lower()

        ok, message = validate_password_policy(new_password)
        if not ok:
            flash(message, "danger")
            return render_template("activate_account.html", user_id=user_id)
        if new_password != confirm_password:
            flash("Les deux mots de passe saisis ne correspondent pas.", "danger")
            return render_template("activate_account.html", user_id=user_id)
        if not EMAIL_REGEX.match(email):
            flash("Adresse email invalide.", "danger")
            return render_template("activate_account.html", user_id=user_id)
        if email != confirm_email:
            flash("Les deux emails saisis ne correspondent pas.", "danger")
            return render_template("activate_account.html", user_id=user_id)

        # Un email ne doit pas être partagé entre deux comptes : sinon l'OTP
        # d'un utilisateur pourrait atterrir dans la boîte d'un autre.
        existing = _safe_find_one("users", {"email": email})
        if existing and str(existing.get("user_id")) != str(user_id):
            flash("Cet email est déjà associé à un autre compte.", "danger")
            return render_template("activate_account.html", user_id=user_id)

        update = {
            "password_hash": hash_password(new_password),
            "email": email,
            "account_activated": True,
        }
        try:
            # Filtre atomique : n'active le compte que s'il ne l'était pas déjà,
            # pour éviter toute double-activation en cas de double-soumission
            # (double-clic, rejeu du formulaire, onglets multiples).
            result = get_collection("users").update_one(
                {"user_id": user_id, "account_activated": {"$ne": True}},
                {"$set": update},
            )
            if result.matched_count == 0:
                flash("Ce compte a déjà été activé entre-temps. Veuillez vous reconnecter.", "warning")
                return redirect(url_for("login_page"))
        except Exception as exc:
            flash(f"Impossible d'enregistrer les informations du compte : {exc}", "danger")
            return render_template("activate_account.html", user_id=user_id)

        log_account_event(user_id, "account_activated", request.remote_addr or "0.0.0.0")

        # Compte activé : on enchaîne directement sur le flux MFA existant.
        session.pop("pending_activation_user_id", None)
        session["pending_user_id"] = user_id
        activated_user = dict(user)
        activated_user.update(update)
        if _mfa_enabled(activated_user):
            _prepare_mfa_challenge(activated_user)
            flash("Compte activé. Un code OTP a été envoyé à votre nouvelle adresse email.", "success")
            return redirect(url_for("verify_otp_page"))
        _open_session(activated_user, mfa_ok=False)
        return redirect(url_for("dashboard"))

    return render_template("activate_account.html", user_id=user_id)


@app.route("/healthz")
def healthz():
    """Route de santé pour les probes des hébergeurs gratuits (Render/Railway/Koyeb)."""
    return jsonify({"status": "ok"}), 200


def _open_session(user, mfa_ok):
    token_secret = session.pop("pending_totp_secret", None)
    session.clear()
    if token_secret and not user.get("totp_secret"):
        session["pending_totp_secret"] = token_secret
    session["user_id"] = user["user_id"]
    session["mfa_ok"] = mfa_ok
    session["login_time"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    session["token"] = create_jwt(user["user_id"], user["role"], user["department"], mfa_ok=mfa_ok)
    session.pop("pending_user_id", None)
    session.pop("pending_totp_secret", None)


@app.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("5 per 5 minutes", methods=["POST"])
def verify_otp_page():
    user = _safe_find_one("users", {"user_id": session.get("pending_user_id")})
    if not user:
        return redirect(url_for("login_page"))
    secret = _get_totp_secret(user)
    if not secret:
        flash("Impossible de générer le code OTP.", "danger")
        return redirect(url_for("login_page"))
    if request.method == "POST":
        otp = request.form.get("otp", "").strip()
        if not verify_totp(secret, otp):
            _record_login_event(user["user_id"], user.get("role", "?"), user.get("department", "?"),
                                 success=False, mfa_passed=False, reason="Code OTP invalide ou expiré")
            flash("Code OTP invalide ou expiré. Connexion refusée.", "danger")
            return render_template("verify_otp.html", otp_seconds=TOTP_INTERVAL_SECONDS)
        _record_login_event(user["user_id"], user.get("role", "?"), user.get("department", "?"),
                             success=True, mfa_passed=True, reason="Connexion réussie (MFA validé)")
        _open_session(user, mfa_ok=True)
        return redirect(url_for("dashboard"))
    return render_template("verify_otp.html", otp_seconds=TOTP_INTERVAL_SECONDS)


@app.route("/logout")
def logout():
    session.clear(); flash("Session fermée avec succès.", "success")
    return redirect(url_for("login_page"))


@app.route("/dashboard")
@login_required
@role_required(*ALERT_ROLES)
def dashboard():
    departments = sorted(get_alerts_by_department().keys())
    return render_template("dashboard.html", departments=departments)


@app.route("/api/dashboard/summary")
@login_required
@api_role_required(*ALERT_ROLES)
def api_dashboard_summary():
    return jsonify(get_dashboard_summary())


@app.route("/api/dashboard/top-users")
@login_required
@api_role_required(*ALERT_ROLES)
def api_dashboard_top_users():
    n = min(max(int(request.args.get("n", 10)), 1), 50)
    return jsonify(get_top_risky_users(n))


@app.route("/api/dashboard/timeseries")
@login_required
@api_role_required(*ALERT_ROLES)
def api_dashboard_timeseries():
    granularity = request.args.get("granularity", "hour")
    if granularity == "day":
        return jsonify(get_alerts_by_day(30))
    return jsonify(get_alerts_by_hour())


@app.route("/api/dashboard/by-action")
@login_required
@api_role_required(*ALERT_ROLES)
def api_dashboard_by_action():
    return jsonify(get_alerts_by_action())


@app.route("/api/dashboard/by-department")
@login_required
@api_role_required(*ALERT_ROLES)
def api_dashboard_by_department():
    return jsonify(get_alerts_by_department())


@app.route("/api/dashboard/by-risk-level")
@login_required
@api_role_required(*ALERT_ROLES)
def api_dashboard_by_risk_level():
    return jsonify(get_alerts_by_risk_level())


@app.route("/users/<user_id>/alerts")
@login_required
def user_alerts_page(user_id):
    # Chacun ne peut consulter que ses PROPRES alertes ; seuls les rôles
    # de supervision (admin_securite, admin) peuvent consulter celles
    # d'un autre utilisateur (auparavant : n'importe qui, via l'URL).
    viewer = current_user()
    if str(viewer.get("user_id")) != str(user_id) and viewer.get("role") not in ALERT_ROLES:
        flash("Accès refusé : vous ne pouvez consulter que vos propres alertes.", "danger")
        return redirect(url_for("resources_page"))
    alerts = [alert for alert in get_high_risk_alerts() if str(alert.get("user_id")) == str(user_id)]
    return render_template("user_alerts.html", user_id=user_id, alerts=alerts)


@app.route("/dashboard/top-users.csv")
@login_required
@api_role_required(*ALERT_ROLES)
def export_top_users_csv():
    fields = ["user_id", "total_score", "alert_count", "dominant_risk_level", "last_reason"]
    rows = get_top_risky_users(10)
    output = ",".join(fields) + "\n" + "\n".join(",".join(str(row.get(field, "")).replace(",", " ") for field in fields) for row in rows)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=top_risky_users.csv"})


@app.route("/dashboard/alerts.csv")
@login_required
@api_role_required(*ALERT_ROLES)
def export_alerts_csv():
    fields = ["timestamp", "alert_id", "user_id", "department", "action", "risk_score", "risk_level", "risk_reasons"]
    rows = get_high_risk_alerts()
    output = ",".join(fields) + "\n" + "\n".join(",".join(str(row.get(field, "")).replace(",", " ").replace("\n", " ") for field in fields) for row in rows)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=alerts.csv"})


@app.route("/resources")
@login_required
def resources_page():
    user = current_user()
    resources = []
    for resource in _safe_find("resources"):
        item = dict(resource)
        status = _resource_access_preview(user, item)
        # Chacun ne doit voir que les ressources sur lesquelles il a au moins
        # un droit de lecture accordé par la policy RBAC/ABAC — les autres
        # sont masquées plutôt que simplement marquées "Refusé".
        if status not in ("Lecture possible", "MFA requis"):
            continue
        item["access_status"] = status
        resources.append(item)
    return render_template("resources.html", resources=resources)


@app.route("/resources/<resource_id>", methods=["GET", "POST"])
@login_required
def resource_detail(resource_id):
    resource = _safe_find_one("resources", {"resource_id": resource_id})
    if not resource:
        flash("Ressource introuvable.", "danger"); return redirect(url_for("resources_page"))

    user = dict(current_user())
    context = {"mfa_ok": session.get("mfa_ok", False), "hour": datetime.now(timezone.utc).hour}
    ip = request.remote_addr or "0.0.0.0"

    # Le détail complet d'une ressource (y compris son historique d'accès)
    # ne doit être visible qu'aux utilisateurs autorisés à la LIRE — avant,
    # n'importe quel utilisateur connecté pouvait ouvrir n'importe quelle
    # fiche en devinant/tapant son URL, RBAC/ABAC n'étant vérifié qu'au clic
    # sur "Tester l'accès".
    ok, reason = authorize(user, resource, "read", context, ip)
    if not ok:
        flash(f"Accès refusé à cette ressource : {reason}", "danger")
        return redirect(url_for("resources_page"))

    decision = None
    if request.method == "POST":
        ok, reason = authorize(user, resource, "read", context, ip)
        decision = {"ok": ok, "reason": reason}
        flash(reason, "success" if ok else "danger")
    history = [l for l in _safe_find("access_logs") if l.get("resource_id") == resource_id][-10:]
    return render_template("resource_detail.html", resource=resource, history=history, decision=decision)


@app.route("/audit-logs")
@login_required
@role_required(*AUDIT_ROLES)
def audit_logs_page():
    logs = sorted(_safe_find("access_logs"), key=lambda x: x.get("timestamp", ""), reverse=True)
    denies_by_user = {}
    for l in logs:
        if str(l.get("success")).lower() == "false": denies_by_user[l.get("user_id", "?")] = denies_by_user.get(l.get("user_id", "?"), 0) + 1
    return render_template("audit_logs.html", logs=logs[:250], denies_by_user=denies_by_user)


@app.route("/audit-logs/export.csv")
@login_required
@role_required(*AUDIT_ROLES)
def export_audit_csv():
    logs = _safe_find("access_logs")
    fields = ["timestamp", "user_id", "role", "department", "resource_id", "resource_type", "sensitivity", "action", "ip", "success", "mfa_passed", "reason"]
    output = ",".join(fields) + "\n" + "\n".join(",".join(str(log.get(f, "")).replace(",", " ") for f in fields) for log in logs)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=audit_logs.csv"})


if __name__ == "__main__":
    print("=== Initialisation de la base MongoDB ===")
    try:
        _init_users(); _init_resources(); _init_logs(); ensure_indexes()
    except Exception as exc:
        print(f"[INIT WARNING] MongoDB indisponible, mode CSV en lecture seule: {exc}")

    # Isolé du bloc ci-dessus : le compte admin doit être créé/synchronisé
    # même si l'import des CSV ou ensure_indexes() échoue pour une autre
    # raison (ex. collections déjà peuplées depuis un TP précédent).
    try:
        ensure_admin_account()
    except Exception as exc:
        print(f"[INIT WARNING] Impossible de créer/synchroniser le compte admin : {exc}")
    print("=== Démarrage du serveur Flask ===")
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", 5000)), debug=os.getenv("FLASK_DEBUG", "true").lower() == "true")
