"""
access/engine.py
Moteur de décision authorize() : combine RBAC, ABAC (département, sensibilité)
et contraintes contextuelles (MFA, horaire).

Ordre des vérifications (fail-fast) :
  1. MFA sur données sensibles/confidentielles
  2. RBAC : action autorisée pour ce rôle ?
  3. RBAC : type de ressource autorisé ?
  4. ABAC : contrainte de département
  5. Contrainte temporelle
"""
from datetime import datetime, timezone
from access.policy import (
    POLICY, MFA_REQUIRED_SENSITIVITIES,
    DEPARTMENT_RESTRICTED_ROLES, HOUR_MIN, HOUR_MAX
)
from audit.logger import log_access

def authorize(user: dict, resource: dict, action: str,
              context: dict, ip: str = "0.0.0.0") -> tuple[bool, str]:
    """
    Décide si l'accès est autorisé.

    Paramètres :
        user     – document utilisateur MongoDB
        resource – document ressource MongoDB
        action   – action demandée (read, write, create, delete, export)
        context  – dict avec au moins : { mfa_ok: bool, hour: int }
        ip       – adresse IP du client

    Retourne :
        (True, "Accès autorisé")  ou  (False, "Raison du refus")
    """
    sensitivity = resource.get("sensitivity", "")
    mfa_ok      = context.get("mfa_ok", False)
    hour        = context.get("hour", datetime.now(timezone.utc).hour)
    role        = user.get("role", "")

    # ── 1. MFA obligatoire pour les ressources sensibles/confidentielles ──────
    if sensitivity in MFA_REQUIRED_SENSITIVITIES and not mfa_ok:
        reason = (
            f"MFA obligatoire pour accéder à une ressource "
            f"de sensibilité '{sensitivity}'"
        )
        _write_log(user, resource, action, ip, success=False,
                   mfa_passed=False, reason=reason)
        return False, reason

    # ── 2. RBAC – l'action est-elle définie pour ce rôle ? ───────────────────
    role_policy = POLICY.get(role, {})
    if action not in role_policy:
        reason = (
            f"Le rôle '{role}' ne peut pas effectuer "
            f"l'action '{action}'"
        )
        _write_log(user, resource, action, ip, success=False,
                   mfa_passed=mfa_ok, reason=reason)
        return False, reason

    # ── 3. RBAC – le type de ressource est-il autorisé pour cette action ? ───
    allowed_types = role_policy[action]
    resource_type = resource.get("type", "")
    if resource_type not in allowed_types:
        reason = (
            f"Le rôle '{role}' n'est pas autorisé à effectuer "
            f"'{action}' sur le type '{resource_type}'"
        )
        _write_log(user, resource, action, ip, success=False,
                   mfa_passed=mfa_ok, reason=reason)
        return False, reason

    # ── 4. ABAC – contrainte de département ───────────────────────────────────
    if role in DEPARTMENT_RESTRICTED_ROLES:
        if user.get("department") != resource.get("owner_department"):
            reason = (
                f"Contrainte ABAC : département utilisateur "
                f"'{user.get('department')}' ≠ département ressource "
                f"'{resource.get('owner_department')}'"
            )
            _write_log(user, resource, action, ip, success=False,
                       mfa_passed=mfa_ok, reason=reason)
            return False, reason

    # ── 5. Contrainte temporelle ──────────────────────────────────────────────
    if hour < HOUR_MIN or hour > HOUR_MAX:
        reason = (
            f"Contrainte temporelle : accès refusé hors plage "
            f"{HOUR_MIN}h–{HOUR_MAX}h (heure courante : {hour}h)"
        )
        _write_log(user, resource, action, ip, success=False,
                   mfa_passed=mfa_ok, reason=reason)
        return False, reason

    # ── Accès autorisé ────────────────────────────────────────────────────────
    reason = "Accès autorisé"
    _write_log(user, resource, action, ip, success=True,
               mfa_passed=mfa_ok, reason=reason)
    return True, reason


def _write_log(user, resource, action, ip, success, mfa_passed, reason):
    """Délègue systématiquement la journalisation à audit/logger.py."""
    log_access(
        user_id=user.get("user_id", "?"),
        role=user.get("role", "?"),
        department=user.get("department", "?"),
        resource_id=resource.get("resource_id", "?"),
        resource_type=resource.get("type", "?"),
        sensitivity=resource.get("sensitivity", "?"),
        action=action,
        ip=ip,
        success=success,
        mfa_passed=mfa_passed,
        reason=reason,
    )