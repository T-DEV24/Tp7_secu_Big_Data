"""
auth/routes.py
Expose /login et /verify-otp.
Aucune logique RBAC/ABAC ici : uniquement l'identité.
"""
from flask import Blueprint, request, jsonify
from db.connection import get_collection
from auth.security import (
    verify_password, verify_totp,
    create_jwt, get_current_totp, TOTP_INTERVAL_SECONDS
)

auth_bp = Blueprint("auth", __name__, url_prefix="/auth")

def _get_user(user_id: str):
    return get_collection("users").find_one({"user_id": user_id}, {"_id": 0})

@auth_bp.route("/login", methods=["POST"])
def login():
    """
    Étape 1 : vérification mot de passe.
    Retourne un token partiel si MFA activée, sinon un JWT complet.
    Corps attendu : { "user_id": "u001", "password": "..." }
    """
    data = request.get_json(force=True)
    user_id  = data.get("user_id", "").strip()
    password = data.get("password", "")

    user = _get_user(user_id)
    if not user:
        return jsonify({"error": "Identifiants invalides"}), 401

    if not verify_password(password, user["password_hash"]):
        return jsonify({"error": "Identifiants invalides"}), 401

    # Si MFA activée, le client doit passer par /verify-otp
    if user.get("mfa_enabled"):
        code = get_current_totp(user["totp_secret"])
        print(
            f"[MFA] Code OTP pour {user_id} : {code} "
            f"(expire dans {TOTP_INTERVAL_SECONDS // 60} minutes)"
        )
        return jsonify({
            "status":   "mfa_required",
            "user_id":  user_id,
            "message":  "Code OTP envoyé dans le terminal du serveur."
        }), 200

    # Pas de MFA : JWT émis directement (mfa_ok = False)
    token = create_jwt(user_id, user["role"], user["department"], mfa_ok=False)
    return jsonify({"token": token}), 200


@auth_bp.route("/verify-otp", methods=["POST"])
def verify_otp():
    """
    Étape 2 MFA : vérification du code TOTP.
    Corps attendu : { "user_id": "u001", "otp": "123456" }
    """
    data    = request.get_json(force=True)
    user_id = data.get("user_id", "").strip()
    otp     = data.get("otp", "").strip()

    user = _get_user(user_id)
    if not user:
        return jsonify({"error": "Utilisateur inconnu"}), 401

    if not verify_totp(user["totp_secret"], otp):
        return jsonify({"error": "Code OTP invalide ou expiré"}), 401

    # MFA réussie : JWT complet avec mfa_ok = True
    token = create_jwt(user_id, user["role"], user["department"], mfa_ok=True)
    return jsonify({"token": token}), 200


@auth_bp.route("/totp-debug/<user_id>", methods=["GET"])
def totp_debug(user_id):
    """Route utilitaire : affiche le code TOTP courant dans le terminal."""
    user = _get_user(user_id)
    if not user:
        return jsonify({"error": "Utilisateur inconnu"}), 404
    code = get_current_totp(user["totp_secret"])
    print(
        f"[MFA DEBUG] Code OTP pour {user_id} : {code} "
        f"(expire dans {TOTP_INTERVAL_SECONDS // 60} minutes)"
    )
    return jsonify({"user_id": user_id, "message": "Code OTP envoyer par mail et affiché dans le terminal au cas ou vous n'etes pas connecter."}), 200
