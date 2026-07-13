"""
access/routes.py
Routes exposant les ressources protégées.
Chaque route valide le JWT puis appelle le moteur de décision
avant de renvoyer la moindre donnée.
"""
from flask import Blueprint, request, jsonify
from db.connection import get_collection
from access.engine import authorize
from auth.security import decode_jwt
import jwt as pyjwt
from datetime import datetime, timezone

access_bp = Blueprint("access", __name__, url_prefix="/access")

def _current_user(token: str):
    """Décode le JWT et retourne le document utilisateur complet."""
    payload = decode_jwt(token)   # lève une exception si invalide
    user = get_collection("users").find_one(
        {"user_id": payload["sub"]}, {"_id": 0}
    )
    if not user:
        raise ValueError("Utilisateur introuvable")
    # Injecte le statut MFA du JWT dans le document utilisateur
    user["mfa_ok"] = payload.get("mfa_ok", False)
    return user

def _bearer(request_obj) -> str:
    """Extrait le token Bearer de l'en-tête Authorization."""
    auth = request_obj.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise ValueError("Token manquant")
    return auth[7:]

@access_bp.route("/resource/<resource_id>", methods=["GET"])
def get_resource(resource_id):
    """
    Accès en lecture à une ressource.
    En-tête requis : Authorization: Bearer <token>
    """
    try:
        token = _bearer(request)
        user  = _current_user(token)
    except (pyjwt.ExpiredSignatureError, pyjwt.InvalidTokenError, ValueError) as e:
        return jsonify({"error": f"Non authentifié : {e}"}), 401

    resource = get_collection("resources").find_one(
        {"resource_id": resource_id}, {"_id": 0}
    )
    if not resource:
        return jsonify({"error": "Ressource introuvable"}), 404

    context = {
        "mfa_ok": user.pop("mfa_ok", False),
        "hour":   datetime.now(timezone.utc).hour,
    }
    ip = request.remote_addr or "0.0.0.0"

    ok, reason = authorize(user, resource, "read", context, ip)
    if not ok:
        return jsonify({"error": reason}), 403

    return jsonify({"resource": resource, "reason": reason}), 200


@access_bp.route("/resource/<resource_id>", methods=["PUT"])
def write_resource(resource_id):
    """Modification d'une ressource (action write)."""
    try:
        token = _bearer(request)
        user  = _current_user(token)
    except (pyjwt.ExpiredSignatureError, pyjwt.InvalidTokenError, ValueError) as e:
        return jsonify({"error": f"Non authentifié : {e}"}), 401

    resource = get_collection("resources").find_one(
        {"resource_id": resource_id}, {"_id": 0}
    )
    if not resource:
        return jsonify({"error": "Ressource introuvable"}), 404

    context = {
        "mfa_ok": user.pop("mfa_ok", False),
        "hour":   datetime.now(timezone.utc).hour,
    }
    ip = request.remote_addr or "0.0.0.0"

    ok, reason = authorize(user, resource, "write", context, ip)
    if not ok:
        return jsonify({"error": reason}), 403

    updates = request.get_json(force=True) or {}
    get_collection("resources").update_one(
        {"resource_id": resource_id}, {"$set": updates}
    )
    return jsonify({"message": "Ressource mise à jour", "reason": reason}), 200


@access_bp.route("/export/journal", methods=["GET"])
def export_journal():
    """Export du journal d'accès (réservé à admin_securite)."""
    try:
        token = _bearer(request)
        user  = _current_user(token)
    except (pyjwt.ExpiredSignatureError, pyjwt.InvalidTokenError, ValueError) as e:
        return jsonify({"error": f"Non authentifié : {e}"}), 401

    fake_resource = {
        "resource_id":      "journal_acces",
        "type":             "journal_acces",
        "owner_department": "it",
        "sensitivity":      "confidentiel",
    }
    context = {
        "mfa_ok": user.pop("mfa_ok", False),
        "hour":   datetime.now(timezone.utc).hour,
    }
    ip = request.remote_addr or "0.0.0.0"

    ok, reason = authorize(user, fake_resource, "export", context, ip)
    if not ok:
        return jsonify({"error": reason}), 403

    logs = list(get_collection("access_logs").find({}, {"_id": 0}))
    return jsonify({"logs": logs, "count": len(logs)}), 200