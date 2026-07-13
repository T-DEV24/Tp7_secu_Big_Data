# Interprétation enrichie du dashboard

Le dashboard priorise les alertes dont le `risk_score` est supérieur ou égal à 6, car ce seuil concentre les événements nécessitant une action de sécurité. Les indicateurs 24h, 7j et 30j permettent de distinguer un incident ponctuel d'une dérive durable des comportements d'accès.

Les graphiques par action, par heure et par département doivent être lus ensemble : une concentration hors heures ouvrées indique un besoin de fenêtre d'accès applicative, tandis qu'une concentration par département suggère une revue RBAC/ABAC ciblée. Les raisons de risque récurrentes comme `mfa_non_valide`, `ip_externe` ou `hors_heures_ouvrees` orientent directement les remédiations.

Les mesures de contrôle d'accès à renforcer en priorité sont donc le réenrôlement MFA des comptes à risque, la restriction VPN ou liste blanche pour les IP externes, le verrouillage progressif par utilisateur, et une revue des droits des départements exposés dans le top des alertes.
