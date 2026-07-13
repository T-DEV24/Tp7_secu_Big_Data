"""
auth/mailer.py
Envoi du code OTP par email via l'API HTTP Brevo (fonctionne sur Render free tier,
contrairement au SMTP direct qui est bloqué depuis sept. 2025).
Fallback automatique en SMTP si BREVO_API_KEY absent (utile en local).
"""
import os
import smtplib
from email.mime.text import MIMEText

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
BREVO_API_KEY = os.getenv("BREVO_API_KEY")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def _send_via_brevo(user_id: str, code: str, minutes_validite: int, recipient_email: str) -> bool:
    import requests
    try:
        resp = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": BREVO_API_KEY, "Content-Type": "application/json"},
            json={
                "sender": {"email": EMAIL_SENDER},
                "to": [{"email": recipient_email}],
                "subject": f"Code OTP - {user_id} - Hopital App",
                "textContent": (
                    f"Utilisateur : {user_id}\n"
                    f"Code de vérification : {code}\n"
                    f"Il expire dans {minutes_validite} minutes.\n\n"
                    f"Si vous n'êtes pas à l'origine de cette demande, ignorez ce message."
                ),
            },
            timeout=8,
        )
        return resp.status_code in (200, 201)
    except Exception as e:
        print(f"[MFA] Echec envoi Brevo : {e}")
        return False


def _send_via_smtp(user_id: str, code: str, minutes_validite: int, recipient_email: str) -> bool:
    msg = MIMEText(
        f"Utilisateur : {user_id}\n"
        f"Code de vérification : {code}\n"
        f"Il expire dans {minutes_validite} minutes.\n\n"
        f"Si vous n'êtes pas à l'origine de cette demande, ignorez ce message."
    )
    msg["Subject"] = f"Code OTP - {user_id} - Hopital App"
    msg["From"] = EMAIL_SENDER
    msg["To"] = recipient_email
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=8) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_APP_PASSWORD)
            server.sendmail(EMAIL_SENDER, [recipient_email], msg.as_string())
        return True
    except Exception as e:
        print(f"[MFA] Echec envoi SMTP : {e}")
        return False


def send_otp_email(user_id: str, code: str, minutes_validite: int = 3, recipient_email: str = None) -> bool:
    if not EMAIL_SENDER or not recipient_email:
        print(f"[MFA] Config email incomplète ou aucun email pour {user_id}.")
        return False
    if BREVO_API_KEY:
        return _send_via_brevo(user_id, code, minutes_validite, recipient_email)
    if EMAIL_APP_PASSWORD:
        return _send_via_smtp(user_id, code, minutes_validite, recipient_email)
    print("[MFA] Ni BREVO_API_KEY ni EMAIL_APP_PASSWORD configurés.")
    return False
