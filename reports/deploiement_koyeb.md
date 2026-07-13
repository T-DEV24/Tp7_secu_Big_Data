# Guide de déploiement Koyeb — TP7_secure

1. Pousser la branche GitHub contenant l'application Flask.
2. Dans Koyeb, créer une nouvelle application depuis le dépôt GitHub.
3. Choisir un service Web avec la commande de démarrage `gunicorn main:app --bind 0.0.0.0:$PORT` (ou laisser Koyeb détecter le `Procfile`).
4. Définir les variables d'environnement : `MONGO_URI`, `DB_NAME`, `FLASK_SECRET_KEY`, `JWT_SECRET`, `EMAIL_SENDER`, `EMAIL_APP_PASSWORD`, `SESSION_COOKIE_SECURE=true`, `FLASK_DEBUG=false`, `KAFKA_BOOTSTRAP_SERVERS`, `KAFKA_TOPIC`, `ALERT_SCORE_THRESHOLD`.
   Il n'y a plus de variable `OTP_RECIPIENT` : chaque utilisateur reçoit son OTP
   sur l'email personnel qu'il renseigne lors de l'activation de son compte.
5. Vérifier que Koyeb active automatiquement HTTPS sur le domaine fourni.
6. Tester `/healthz` (doit répondre `200`), puis `/login` → `/activate-account`
   (première connexion) → `/verify-otp` → `/dashboard`, ainsi que les exports CSV.
7. Insérer ici l'URL finale et une capture d'écran de preuve de déploiement lorsque le service est publié : **URL à compléter après déploiement réel**.
