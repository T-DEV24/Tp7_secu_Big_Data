from datetime import datetime, timedelta, timezone
import re

import pytest

import main
from auth.security import validate_password_policy


class FakeUsersCollection:
    def __init__(self, user):
        self.user = user

    def update_one(self, query, update):
        for key, value in update.get("$set", {}).items():
            self.user[key] = value
        for key in update.get("$unset", {}):
            self.user.pop(key, None)


@pytest.fixture
def client(monkeypatch):
    main.app.config.update(TESTING=True, WTF_CSRF_ENABLED=True)
    if hasattr(main.limiter, "_hits"):
        main.limiter._hits.clear()
    return main.app.test_client()


def _csrf_from_login(client):
    response = client.get("/login")
    html = response.get_data(as_text=True)
    return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)


def test_security_headers_on_login(client):
    response = client.get("/login", base_url="https://localhost")
    assert response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert "Strict-Transport-Security" in response.headers


def test_login_rate_limit_after_five_bad_attempts(client, monkeypatch):
    monkeypatch.setattr(main, "_safe_find_one", lambda *_args, **_kwargs: None)
    token = _csrf_from_login(client)
    statuses = [
        client.post("/login", data={"user_id": "missing", "password": "bad", "csrf_token": token}).status_code
        for _ in range(6)
    ]
    assert statuses[:5] == [200] * 5
    assert statuses[5] == 429


def test_post_without_csrf_is_rejected(client):
    response = client.post("/login", data={"user_id": "u001", "password": "bad"})
    assert response.status_code in {400, 403}


def test_account_lockout_and_unlock(monkeypatch):
    user = {
        "user_id": "u001",
        "failed_attempts": 4,
        "password_hash": "irrelevant",
        "role": "medecin",
        "department": "cardiologie",
    }
    monkeypatch.setattr(main, "get_collection", lambda _name: FakeUsersCollection(user))
    main._record_failed_login(user)
    assert user["failed_attempts"] == 5
    assert main._is_account_locked(user)

    user["locked_until"] = datetime.now(timezone.utc) - timedelta(seconds=1)
    assert not main._is_account_locked(user)


def test_password_policy_requires_length_and_three_classes():
    assert validate_password_policy("short1A!")[0] is False
    assert validate_password_policy("onlylowercasepassword")[0] is False
    assert validate_password_policy("LongEnough123")[0] is True
