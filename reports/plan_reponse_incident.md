# Plan de réponse à incident — TP7 Contrôle d'accès & Big Data

Ce plan exploite les alertes produites par les règles de `spark_jobs/risk_scoring.py` lorsque le `risk_score` atteint le seuil critique de 6 ou plus.

## 1. Détection

- **Action immédiate :** surveiller les alertes `risk_level=élevé` dans MongoDB et prioriser les événements combinant IP externe, échec MFA, accès hors heures ouvrées et ressource sensible.
- **Action préventive :** conserver des tableaux de bord par heure, action et département afin d'identifier les dérives avant saturation du SOC.

## 2. Confinement

- **Action immédiate :** suspendre temporairement les comptes dont le score cumulé est le plus élevé et révoquer leurs sessions actives.
- **Action préventive :** appliquer un verrouillage progressif après échecs répétés par utilisateur, en complément du rate limiting par IP.

## 3. Éradication

- **Action immédiate :** réinitialiser les facteurs MFA et secrets TOTP des comptes compromis, puis vérifier les droits RBAC/ABAC associés.
- **Action préventive :** renforcer les règles de moindre privilège pour les rôles accédant aux ressources sensibles ou confidentielles.

## 4. Remédiation

- **Action immédiate :** corriger les politiques d'accès ayant permis l'événement, notamment les plages horaires, les restrictions par département et les contrôles MFA.
- **Action préventive :** ajouter des index MongoDB sur les champs de requête fréquents pour accélérer les investigations pendant crise.

## 5. Retour d'expérience

- **Action immédiate :** documenter la chronologie, les règles déclenchées, les utilisateurs concernés et les preuves d'export CSV du dashboard.
- **Action préventive :** ajuster les seuils de scoring et enrichir les jeux de tests pour limiter les faux positifs et faux négatifs observés.
