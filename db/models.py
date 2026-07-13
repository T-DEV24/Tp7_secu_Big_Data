"""
db/models.py
Définit la forme attendue des documents MongoDB.
Pas d'ORM : simples fonctions de construction de dicts validés.
"""
from datetime import datetime, timezone

def make_user(user_id, name, role, department, password_hash,
              totp_secret, mfa_enabled=True, clearance="medical",
              email=None, account_activated=False):
    """Structure d'un document utilisateur.

    email et account_activated sont renseignés lors de la première connexion :
    tant que account_activated est False, le mot de passe par défaut (= user_id)
    reste accepté et déclenche le formulaire d'activation de compte.
    """
    return {
        "user_id":            user_id,
        "name":               name,
        "role":               role,
        "department":         department,
        "password_hash":      password_hash,   # jamais en clair
        "totp_secret":        totp_secret,     # secret TOTP individuel
        "mfa_enabled":        mfa_enabled,
        "clearance":          clearance,
        "email":              email,            # email personnel, requis pour l'OTP
        "account_activated":  account_activated,
    }

def make_resource(resource_id, patient_id, rtype,
                  owner_department, sensitivity):
    """Structure d'un document ressource."""
    return {
        "resource_id":       resource_id,
        "patient_id":        patient_id,
        "type":              rtype,
        "owner_department":  owner_department,
        "sensitivity":       sensitivity,   # public | interne | sensible | confidentiel
    }

def make_log(user_id, role, department, resource_id,
             resource_type, sensitivity, action,
             ip, success, mfa_passed, reason):
    """Structure d'une entrée dans access_logs."""
    return {
        "timestamp":     datetime.now(timezone.utc).isoformat(),
        "user_id":       user_id,
        "role":          role,
        "department":    department,
        "resource_id":   resource_id,
        "resource_type": resource_type,
        "sensitivity":   sensitivity,
        "action":        action,
        "ip":            ip,
        "success":       success,
        "mfa_passed":    mfa_passed,
        "reason":        reason,
    }