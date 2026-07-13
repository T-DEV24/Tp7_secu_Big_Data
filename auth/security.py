"""
auth/security.py
Hachage de mot de passe (bcrypt) et gestion TOTP (pyotp).
Isolé pour être testable indépendamment.
"""
try:
    import bcrypt
except ImportError:
    bcrypt = None
try:
    import pyotp
except ImportError:
    pyotp = None
try:
    import jwt
except ImportError:
    jwt = None
import os
from datetime import datetime, timedelta, timezone

JWT_SECRET  = os.getenv("JWT_SECRET", "change_me_in_production")
JWT_ALGO    = "HS256"
JWT_EXPIRY  = int(os.getenv("JWT_EXPIRY_MINUTES", 60))
TOTP_INTERVAL_SECONDS = int(os.getenv("TOTP_INTERVAL_SECONDS", 300))


# ─── Politique de mot de passe ───────────────────────────────────────────────

PASSWORD_MIN_LENGTH = 12

def password_complexity_classes(password: str) -> int:
    """Compte les classes présentes: minuscule, majuscule, chiffre, symbole."""
    checks = [
        any(ch.islower() for ch in password),
        any(ch.isupper() for ch in password),
        any(ch.isdigit() for ch in password),
        any(not ch.isalnum() for ch in password),
    ]
    return sum(checks)

def validate_password_policy(password: str) -> tuple[bool, str]:
    """Valide la politique TP7: 12 caractères et au moins 3 classes sur 4."""
    if len(password or "") < PASSWORD_MIN_LENGTH:
        return False, "Le mot de passe doit contenir au moins 12 caractères."
    if password_complexity_classes(password) < 3:
        return False, "Le mot de passe doit contenir au moins 3 classes: minuscule, majuscule, chiffre, symbole."
    return True, "Mot de passe conforme."

# ─── Hachage de mot de passe ──────────────────────────────────────────────────

def hash_password(plain: str) -> str:
    """Hache le mot de passe avec bcrypt. Ne jamais stocker le mot de passe en clair."""
    if bcrypt is None:
        raise RuntimeError("bcrypt is required to hash passwords")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(plain.encode(), salt).decode()

def verify_password(plain: str, hashed: str) -> bool:
    """Vérifie qu'un mot de passe correspond au hash stocké."""
    if bcrypt is None:
        return False
    return bcrypt.checkpw(plain.encode(), hashed.encode())

# ─── TOTP (MFA) ───────────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """Génère un secret TOTP aléatoire unique à stocker par utilisateur."""
    if pyotp is None:
        raise RuntimeError("pyotp is required to generate TOTP secrets")
    return pyotp.random_base32()

def get_totp_uri(secret: str, username: str, issuer: str = "Hopital") -> str:
    """Retourne l'URI otpauth:// pour générer un QR code."""
    if pyotp is None:
        raise RuntimeError("pyotp is required for TOTP operations")
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS)
    return totp.provisioning_uri(name=username, issuer_name=issuer)

def verify_totp(secret: str, code: str) -> bool:
    """
    Vérifie le code TOTP fourni par l'utilisateur.
    Le code expire après 5 minutes par défaut (TOTP_INTERVAL_SECONDS).
    """
    if pyotp is None:
        return False
    totp = pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS)
    return totp.verify(code, valid_window=0)

def get_current_totp(secret: str) -> str:
    """Renvoie le code TOTP courant (utile pour les tests)."""
    if pyotp is None:
        raise RuntimeError("pyotp is required for TOTP operations")
    return pyotp.TOTP(secret, interval=TOTP_INTERVAL_SECONDS).now()

# ─── JWT ──────────────────────────────────────────────────────────────────────

def create_jwt(user_id: str, role: str, department: str, mfa_ok: bool) -> str:
    """
    Émet un JWT signé contenant l'identité et le statut MFA.
    Le JWT prouve l'identité ; c'est le moteur RBAC/ABAC qui décide de l'accès.
    """
    payload = {
        "sub":        user_id,
        "role":       role,
        "department": department,
        "mfa_ok":     mfa_ok,
        "exp":        datetime.now(timezone.utc) + timedelta(minutes=JWT_EXPIRY),
        "iat":        datetime.now(timezone.utc),
    }
    if jwt is None:
        raise RuntimeError("PyJWT is required to create JWTs")
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_jwt(token: str) -> dict:
    """
    Décode et valide le JWT.
    Lève jwt.ExpiredSignatureError ou jwt.InvalidTokenError si invalide.
    """
    if jwt is None:
        raise RuntimeError("PyJWT is required to decode JWTs")
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
