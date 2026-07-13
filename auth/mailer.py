"""
auth/mailer.py
Envoi du code OTP par email (Gmail SMTP).

Chaque OTP est envoyé à l'email PERSONNEL de l'utilisateur concerné (users.email),
renseigné lors de l'activation de son compte. Il n'y a plus de destinataire fixe.
"""
import os
import smtplib
from email.mime.text import MIMEText

EMAIL_SENDER = os.getenv("EMAIL_SENDER")
EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587


def send_otp_email(user_id: str, code: str, minutes_validite: int = 3, recipient_email: str = None) -> bool:
    """
    Envoie le code OTP par email au destinataire fourni (recipient_email),
    c'est-à-dire l'email personnel stocké pour cet utilisateur.
    Retourne True si l'envoi a réussi.
    """
    if not EMAIL_SENDER or not EMAIL_APP_PASSWORD:
        print("[MFA] EMAIL_SENDER / EMAIL_APP_PASSWORD non configurés.")
        return False
    if not recipient_email:
        print(f"[MFA] Aucun email enregistré pour {user_id} : impossible d'envoyer l'OTP par email.")
        return False

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
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_APP_PASSWORD)
            server.sendmail(EMAIL_SENDER, [recipient_email], msg.as_string())
        return True
    except Exception as e:
        print(f"[MFA] Echec envoi email : {e}")
        return False