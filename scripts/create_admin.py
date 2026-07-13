"""
scripts/create_admin.py
Crée (ou met à jour) un compte administrateur applicatif fixe :

  - user_id            : admin
  - mot de passe        : admin (haché en bcrypt, PAS le mot de passe par
                           défaut = user_id, donc jamais concerné par le
                           flux "première connexion / nouveau mot de passe")
  - account_activated   : True dès la création -> aucune demande de
                           changement de mot de passe au premier login
  - email (OTP)          : tcheuatatcheudjoclotaire@gmail.com (fixe, ne
                           dépend d'aucune saisie utilisateur)
  - role                : admin (accès dashboard alertes + journal d'accès,
                           voir access/policy.py)

Idempotent : peut être relancé sans dupliquer le compte (upsert sur user_id).

Usage :
    cd TP7_new
    python scripts/create_admin.py
(nécessite MONGO_URI / DB_NAME correctement configurés dans .env, comme le
reste de l'application — voir db/connection.py)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import bcrypt
import pyotp
from dotenv import load_dotenv

load_dotenv()

from db.connection import get_collection  # noqa: E402
from db.models import make_user  # noqa: E402

ADMIN_USER_ID = "admin"
ADMIN_PASSWORD = "admin"
ADMIN_EMAIL = "tcheuatatcheudjoclotaire@gmail.com"


def ensure_admin_account(verbose: bool = True) -> None:
    """Upsert idempotent du compte admin fixe. Appelée au démarrage de
    main.py (voir __main__) ET utilisable en script autonome, pour que le
    compte existe aussi bien sur une base déjà remplie que sur une base
    fraîchement initialisée."""
    doc = make_user(
        user_id=ADMIN_USER_ID,
        name="Administrateur",
        role="admin",
        department="direction",
        password_hash=bcrypt.hashpw(ADMIN_PASSWORD.encode(), bcrypt.gensalt()).decode(),
        totp_secret=pyotp.random_base32(),
        mfa_enabled=True,
        clearance="admin",
        email=ADMIN_EMAIL,
        account_activated=True,  # pas de formulaire "nouveau mot de passe"
    )
    # On ne régénère pas totp_secret/password_hash si le compte existe déjà,
    # pour ne pas invalider un mot de passe changé manuellement entre-temps.
    existing = get_collection("users").find_one({"user_id": ADMIN_USER_ID})
    if existing:
        doc["password_hash"] = existing.get("password_hash", doc["password_hash"])
        doc["totp_secret"] = existing.get("totp_secret", doc["totp_secret"])

    result = get_collection("users").update_one(
        {"user_id": ADMIN_USER_ID},
        {"$set": doc},
        upsert=True,
    )
    if not verbose:
        return
    if result.upserted_id is not None:
        print(f"[INIT] Compte '{ADMIN_USER_ID}' créé.")
    else:
        print(f"[INIT] Compte '{ADMIN_USER_ID}' déjà présent (vérifié/synchronisé).")


if __name__ == "__main__":
    ensure_admin_account()
    print(f"      Mot de passe (si nouvellement créé) : {ADMIN_PASSWORD}")
    print(f"      OTP envoyé à : {ADMIN_EMAIL}")
    print("      Accès : dashboard des alertes + journal d'accès (access_log)")
