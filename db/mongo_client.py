"""Compatibilité historique pour la création des index MongoDB TP7."""
from db.ensure_indexes import ensure_indexes


def ensure_alerts_indexes() -> None:
    ensure_indexes()
