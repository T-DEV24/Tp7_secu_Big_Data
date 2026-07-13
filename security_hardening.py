"""Security hardening helpers for the Flask TP7 application."""
import hmac
import os
import secrets
import time
from datetime import timedelta
from functools import wraps

from flask import abort, g, request, session

try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ImportError:  # pragma: no cover - exercised when optional deps are unavailable
    def get_remote_address():
        return request.remote_addr or "127.0.0.1"

    class Limiter:
        def __init__(self, key_func=None, default_limits=None):
            self.key_func = key_func or get_remote_address
            self._hits = {}

        def init_app(self, app):
            app.extensions = getattr(app, "extensions", {})
            app.extensions["limiter"] = self

        def limit(self, limit_value, methods=None, key_func=None):
            count, _, window, _ = limit_value.split()
            max_hits = int(count)
            seconds = int(window) * 60 if "minute" in limit_value else int(window)
            methods = set(methods or [])

            def decorator(view):
                @wraps(view)
                def wrapped(*args, **kwargs):
                    if methods and request.method not in methods:
                        return view(*args, **kwargs)
                    ident = (key_func or self.key_func)()
                    now = time.time()
                    bucket_key = (view.__name__, ident)
                    hits = [ts for ts in self._hits.get(bucket_key, []) if now - ts < seconds]
                    if len(hits) >= max_hits:
                        abort(429)
                    hits.append(now)
                    self._hits[bucket_key] = hits
                    return view(*args, **kwargs)
                return wrapped
            return decorator

try:
    from flask_wtf import CSRFProtect
except ImportError:  # pragma: no cover
    class CSRFProtect:
        def __init__(self):
            self._exempt_blueprints = set()

        def init_app(self, app):
            app.jinja_env.globals["csrf_token"] = _csrf_token

            @app.before_request
            def _fallback_csrf_check():
                if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
                    return None
                if request.blueprint in self._exempt_blueprints:
                    return None
                expected = session.get("csrf_token")
                provided = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
                if not expected or not provided or not hmac.compare_digest(expected, provided):
                    abort(400)
                return None

        def exempt(self, view_or_blueprint):
            name = getattr(view_or_blueprint, "name", None)
            if name:
                self._exempt_blueprints.add(name)
            return view_or_blueprint


def _csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    g.csrf_token = token
    return token

csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, default_limits=[])

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data:; font-src 'self' https://cdn.jsdelivr.net data:; "
        "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def configure_security(app):
    """Apply cookies, CSRF, rate limiting and HTTP security headers."""
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", 3600)
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = _secure_cookie_enabled(app)
    app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(hours=1))

    csrf.init_app(app)
    limiter.init_app(app)

    @app.after_request
    def add_security_headers(response):
        for header, value in SECURITY_HEADERS.items():
            response.headers.setdefault(header, value)
        if request.is_secure or app.config.get("SESSION_COOKIE_SECURE"):
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    return app


def _secure_cookie_enabled(app):
    configured = os.getenv("SESSION_COOKIE_SECURE")
    if configured is not None:
        return configured.lower() in {"1", "true", "yes", "on"}
    return not app.debug and os.getenv("FLASK_ENV") != "development"
