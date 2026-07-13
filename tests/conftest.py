"""
tests/conftest.py
Réinitialise l'état du rate limiter avant chaque test pour éviter toute
contamination entre tests (compteurs partagés par IP/vue entre fichiers de test).
"""
import pytest

import main


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    if hasattr(main.limiter, "reset"):
        main.limiter.reset()
    elif hasattr(main.limiter, "_hits"):
        main.limiter._hits.clear()
    yield
