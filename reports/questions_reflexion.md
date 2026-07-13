# Réponses aux questions de réflexion — TP7

## 1. Pourquoi Kafka pour le flux continu ?

Kafka découple la production des logs d'accès et leur consommation analytique. Il absorbe les pics d'événements, conserve un historique rejouable et permet de brancher plusieurs consommateurs sans modifier l'application Flask.

## 2. Pourquoi Spark pour la corrélation à grande échelle ?

Spark traite efficacement des volumes importants et corrèle les événements avec les référentiels utilisateurs, ressources et politiques. Sa logique distribuable est adaptée au calcul de `risk_score` sur des flux ou lots volumineux.

## 3. Quelles sont les limites du scoring par règles ?

Les règles explicites sont auditables mais peuvent générer des faux positifs lorsque le contexte métier est légitime. Elles peuvent aussi produire des faux négatifs si une attaque ne correspond à aucun motif prévu.

## 4. Quels champs exclure des logs ?

Les mots de passe, OTP, tokens JWT, secrets TOTP, données patient nominatives, diagnostics et informations médicales détaillées doivent être exclus. Les alertes ne conservent que les champs nécessaires à la supervision.

## 5. Quelles mesures de contrôle d'accès renforcer ?

Les mesures prioritaires sont le MFA obligatoire sur ressources sensibles, la restriction des accès hors heures ouvrées, la limitation des IP externes et la vérification stricte des départements autorisés.

## 6. Comment améliorer le dispositif ?

Le dispositif peut évoluer vers un modèle hybride : règles explicables pour la conformité, apprentissage statistique pour détecter les anomalies inédites, et réponse automatisée graduée selon le score cumulé.
