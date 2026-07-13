"""
tests/test_account_activation.py
Vérifie le nouveau parcours de connexion en deux étapes :
login (mot de passe par défaut = user_id) -> activation du compte
(nouveau mot de passe + email) -> MFA.
"""
import re

import bcrypt
import pytest

import main
from auth.mailer import send_otp_email


class FakeUsersCollection:
    """Simule get_collection("users") avec un seul utilisateur en mémoire."""

    def __init__(self, user):
        self.user = dict(user)

    def find_one(self, query, projection=None):
        if all(str(self.user.get(k)) == str(v) for k, v in query.items()):
            return dict(self.user)
        return None

    def update_one(self, query, update):
        class _Result:
            def __init__(self, matched_count):
                self.matched_count = matched_count

        def _matches(field, expected):
            if isinstance(expected, dict) and "$ne" in expected:
                return self.user.get(field) != expected["$ne"]
            return str(self.user.get(field)) == str(expected)

        if not all(_matches(k, v) for k, v in query.items()):
            return _Result(0)

        for key, value in update.get("$set", {}).items():
            self.user[key] = value
        for key in update.get("$unset", {}):
            self.user.pop(key, None)
        return _Result(1)


def _make_pending_user():
    return {
        "user_id": "u001",
        "name": "Dr Ali",
        "role": "medecin",
        "department": "cardiologie",
        "password_hash": bcrypt.hashpw(b"u001", bcrypt.gensalt()).decode(),
        "totp_secret": "JBSWY3DPEHPK3PXP",
        "mfa_enabled": True,
        "account_activated": False,
        "email": None,
    }


@pytest.fixture
def client():
    main.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    if hasattr(main.limiter, "_hits"):
        main.limiter._hits.clear()
    return main.app.test_client()


def _csrf(client, path):
    html = client.get(path).get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def test_default_password_redirects_to_activation(client, monkeypatch):
    user = _make_pending_user()
    monkeypatch.setattr(main, "_safe_find_one", lambda *_a, **_k: dict(user))
    monkeypatch.setattr(main, "get_collection", lambda _name: FakeUsersCollection(user))

    token = _csrf(client, "/login")
    response = client.post(
        "/login",
        data={"user_id": "u001", "password": "u001", "csrf_token": token},
    )
    assert response.status_code == 302
    assert "/activate-account" in response.headers["Location"]


def test_activation_rejects_weak_password(client, monkeypatch):
    user = _make_pending_user()
    fake_col = FakeUsersCollection(user)
    monkeypatch.setattr(main, "_safe_find_one", lambda *_a, **_k: dict(fake_col.user))
    monkeypatch.setattr(main, "get_collection", lambda _name: fake_col)

    with client.session_transaction() as sess:
        sess["pending_activation_user_id"] = "u001"

    token = _csrf(client, "/activate-account")
    response = client.post(
        "/activate-account",
        data={
            "new_password": "short",
            "confirm_password": "short",
            "email": "ali@hopital.fr",
            "confirm_email": "ali@hopital.fr",
            "csrf_token": token,
        },
    )
    assert response.status_code == 200
    assert fake_col.user["account_activated"] is False


def test_activation_success_stores_email_and_hashes_password(client, monkeypatch):
    user = _make_pending_user()
    fake_col = FakeUsersCollection(user)
    monkeypatch.setattr(main, "_safe_find_one", lambda *_a, **_k: dict(fake_col.user))
    monkeypatch.setattr(main, "get_collection", lambda _name: fake_col)
    monkeypatch.setattr(main, "send_otp_email", lambda *_a, **_k: True)
    monkeypatch.setattr(main, "log_account_event", lambda *_a, **_k: None)

    with client.session_transaction() as sess:
        sess["pending_activation_user_id"] = "u001"

    token = _csrf(client, "/activate-account")
    response = client.post(
        "/activate-account",
        data={
            "new_password": "NouveauMotDePasse123!",
            "confirm_password": "NouveauMotDePasse123!",
            "email": "ali@hopital.fr",
            "confirm_email": "ali@hopital.fr",
            "csrf_token": token,
        },
    )
    assert response.status_code == 302
    assert "/verify-otp" in response.headers["Location"]
    assert fake_col.user["account_activated"] is True
    assert fake_col.user["email"] == "ali@hopital.fr"
    assert fake_col.user["password_hash"] != user["password_hash"]


def test_otp_email_requires_recipient(monkeypatch):
    monkeypatch.setattr("auth.mailer.EMAIL_SENDER", "sender@example.com")
    monkeypatch.setattr("auth.mailer.EMAIL_APP_PASSWORD", "app-password")
    assert send_otp_email("u001", "123456", 3, recipient_email=None) is False


def test_default_password_rejected_once_account_is_activated(client, monkeypatch):
    """Régression : après activation, 'user_id' comme mot de passe ne doit plus
    jamais authentifier, seul le vrai mot de passe (haché) doit fonctionner."""
    user = _make_pending_user()
    user["account_activated"] = True
    user["email"] = "ali@hopital.fr"
    # Le hash correspond à un VRAI mot de passe, différent de user_id.
    user["password_hash"] = bcrypt.hashpw(b"NouveauMotDePasse123!", bcrypt.gensalt()).decode()
    monkeypatch.setattr(main, "_safe_find_one", lambda *_a, **_k: dict(user))
    monkeypatch.setattr(main, "get_collection", lambda _name: FakeUsersCollection(user))

    token = _csrf(client, "/login")
    response = client.post(
        "/login",
        data={"user_id": "u001", "password": "u001", "csrf_token": token},
    )
    # Doit être refusé : re-affiche le formulaire de login, pas de redirection.
    assert response.status_code == 200
    assert "Identifiants invalides" in response.get_data(as_text=True)


def test_activation_rejects_email_already_used_by_another_account(client, monkeypatch):
    user = _make_pending_user()
    other_user = {"user_id": "u002", "email": "ali@hopital.fr"}
    fake_col = FakeUsersCollection(user)

    def fake_find_one(collection, query):
        if collection == "users" and "email" in query:
            return dict(other_user)
        return dict(fake_col.user)

    monkeypatch.setattr(main, "_safe_find_one", fake_find_one)
    monkeypatch.setattr(main, "get_collection", lambda _name: fake_col)

    with client.session_transaction() as sess:
        sess["pending_activation_user_id"] = "u001"

    token = _csrf(client, "/activate-account")
    response = client.post(
        "/activate-account",
        data={
            "new_password": "NouveauMotDePasse123!",
            "confirm_password": "NouveauMotDePasse123!",
            "email": "ali@hopital.fr",
            "confirm_email": "ali@hopital.fr",
            "csrf_token": token,
        },
    )
    assert response.status_code == 200
    assert fake_col.user["account_activated"] is False
