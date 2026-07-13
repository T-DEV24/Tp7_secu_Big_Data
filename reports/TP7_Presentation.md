# TP7 — Présentation de synthèse

Ce document remplace le fichier PPTX binaire afin que la revue de code reste entièrement textuelle. Il fournit un plan de 11 diapositives prêt à copier dans PowerPoint, LibreOffice Impress ou Google Slides.

## Diapositive 1 — Titre

**TP7 — Contrôle d'accès & Big Data**  
Pipeline Kafka → Spark → MongoDB, scoring de risque, dashboard de supervision et réponse à incident.

## Diapositive 2 — Objectifs du TP

- Superviser les accès à des ressources hospitalières.
- Calculer un score de risque exploitable par une équipe sécurité.
- Visualiser les alertes et prioriser les remédiations.
- Produire un plan de réponse à incident aligné sur les règles de scoring.

## Diapositive 3 — Architecture globale

- Flask fournit l'interface web, les endpoints API et les exports CSV.
- Kafka transporte les événements d'accès en flux continu.
- Spark enrichit les événements et calcule le `risk_score`.
- MongoDB stocke les alertes minimisées pour le dashboard.

## Diapositive 4 — Données minimisées

- Les alertes conservent uniquement les champs nécessaires à la supervision.
- Les mots de passe, OTP, tokens, secrets TOTP et données patient détaillées sont exclus.
- Cette minimisation limite l'impact d'une fuite et facilite la conformité.

## Diapositive 5 — Règles de scoring

- Les alertes critiques sont produites lorsque `risk_score >= 6`.
- Les facteurs surveillés incluent MFA invalide, IP externe, accès hors horaires, sensibilité de la ressource, échecs et contexte métier.
- Le scoring par règles reste explicable pour la soutenance et l'audit.

## Diapositive 6 — Agrégations MongoDB

- Les fonctions d'agrégation centralisent les calculs du dashboard et du notebook.
- Les indicateurs couvrent les alertes par heure, action, niveau, jour et département.
- Le top utilisateurs combine score cumulé, nombre d'alertes et dernière raison observée.

## Diapositive 7 — Dashboard Flask

- KPI : alertes 24h, 7j, 30j, score moyen et utilisateur prioritaire.
- Graphiques Chart.js : heure, action, niveau de risque, tendance et département.
- Tableau top 10 avec lien vers l'historique d'alertes par utilisateur.

## Diapositive 8 — Exports et investigation

- Export CSV du top 10 des utilisateurs à risque.
- Export CSV des alertes complètes minimisées.
- Ces exports servent de preuves dans le rapport de réponse à incident.

## Diapositive 9 — Index MongoDB

- Index unique sparse sur `alert_id`.
- Index sur `risk_score`, `timestamp`, `risk_level` et `department`.
- Index composé `(user_id, risk_score)` pour accélérer les analyses par compte.

## Diapositive 10 — Réponse à incident

- Détection : identifier les alertes critiques.
- Confinement : suspendre les comptes à score cumulé élevé.
- Éradication : réinitialiser MFA et secrets compromis.
- Remédiation : corriger RBAC/ABAC, horaires et restrictions IP.
- Retour d'expérience : ajuster règles et seuils.

## Diapositive 11 — Déploiement Koyeb

- Connecter le dépôt GitHub à Koyeb.
- Démarrer l'application avec `gunicorn main:app`.
- Injecter les variables d'environnement secrètes.
- Vérifier HTTPS, `/login`, `/dashboard` et les exports CSV.
