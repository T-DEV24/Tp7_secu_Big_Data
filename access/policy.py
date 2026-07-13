"""
access/policy.py
Politique RBAC déclarée sous forme de structure de données.
Traduction directe de la matrice sujet/objet/action du TP.

Structure :
  POLICY[role][action] = [liste des types de ressources autorisées]

Niveaux de sensibilité exigeant la MFA : sensible, confidentiel
Plage horaire autorisée : 6h – 20h
"""

# ─── Politique RBAC ───────────────────────────────────────────────────────────
POLICY = {
    "medecin": {
        "read":   ["dossier_medical", "resultat_labo"],
        "write":  ["dossier_medical"],
        "create": [],
        "delete": [],
        "export": [],
    },
    "infirmier": {
        "read":   ["dossier_medical", "resultat_labo"],
        "write":  [],
        "create": [],
        "delete": [],
        "export": [],
    },
    "secretaire": {
        "read":   ["dossier_admin"],
        "write":  ["dossier_admin"],
        "create": ["dossier_admin"],
        "delete": [],
        "export": [],
    },
    "admin_securite": {
        "read":   ["journal_acces"],
        "write":  [],
        "create": [],
        "delete": [],
        "export": ["journal_acces"],
    },
    # Rôle admin applicatif : accès au dashboard de supervision des alertes
    # et au journal d'accès (access_log), au même titre que admin_securite.
    # Volontairement PAS d'accès aux dossiers médicaux/administratifs
    # (principe du moindre privilège).
    "admin": {
        "read":   ["journal_acces"],
        "write":  [],
        "create": [],
        "delete": [],
        "export": ["journal_acces"],
    },
    "patient": {
        "read":   ["dossier_admin"],
        "write":  [],
        "create": [],
        "delete": [],
        "export": [],
    },
}

# ─── Constantes de politique ──────────────────────────────────────────────────
MFA_REQUIRED_SENSITIVITIES = {"sensible", "confidentiel"}

# Rôles soumis à la contrainte ABAC de département
DEPARTMENT_RESTRICTED_ROLES = {"medecin", "infirmier"}

HOUR_MIN = 6   # heure minimale d'accès (incluse)
HOUR_MAX = 20  # heure maximale d'accès (incluse)