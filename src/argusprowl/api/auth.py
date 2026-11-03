"""API-key authentication and role-based authorization middleware."""

from __future__ import annotations

import hmac
import logging
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

_PUBLIC_EXACT_PATHS = frozenset(
    {
        "/", "/health", "/api/v1/health", "/docs", "/docs/oauth2-redirect",
        "/redoc", "/openapi.json", "/favicon.ico", "/favicon.svg", "/robots.txt",
        "/manifest.webmanifest",
    }
)
_PUBLIC_PREFIXES = ("/assets/",)
_VALID_ROLES = frozenset({"viewer", "analyst", "admin"})
_ANALYST_WRITE_PATTERNS = (
    re.compile(r"^/api/v1/alerts/[^/]+/(?:acknowledge|close)$"),
    re.compile(r"^/api/v1/incidents/[^/]+/(?:annotations|close|transition)$"),
    re.compile(r"^/api/v1/entities/[^/]+/[^/]+/annotations$"),
    re.compile(r"^/api/v1/hunts(?:/[^/]+/(?:hypothesis|scope|queries(?:/[^/]+/execute)?|executions|evidence|findings|conclusion|status))?$"),
)


@dataclass(frozen=True, slots=True)
class AuthPrincipal:
    """Identity and role established by a validated API key."""

    subject: str
    role: str
    key_id: str


def _is_public_path(path: str, *, method: str = "GET", accept: str = "") -> bool:
    """Return whether a request may bypass authentication."""
    method = method.upper()
    if method not in {"GET", "HEAD"}:
        return False
    normalized = path.rstrip("/") or "/"
    if normalized == "/api" or normalized.startswith("/api/"):
        return normalized == "/api/v1/health"
    if normalized in _PUBLIC_EXACT_PATHS:
        return True
    if any(normalized.startswith(prefix) for prefix in _PUBLIC_PREFIXES):
        return True
    reserved_prefixes = (
        "/health/", "/docs/", "/redoc/", "/openapi", "/metrics", "/internal/"
    )
    if normalized.startswith(reserved_prefixes):
        return False
    return "text/html" in accept.lower() and "." not in normalized.rsplit("/", 1)[-1]


def _role_allows(role: str, method: str, path: str) -> bool:
    """Apply deny-by-default authorization for protected API operations."""
    method = method.upper()
    if path == "/api/v1/audit":
        return role == "admin" and method in {"GET", "HEAD"}
    if role == "admin":
        return True
    if role == "viewer":
        return method in {"GET", "HEAD"}
    if role == "analyst":
        if method in {"GET", "HEAD"}:
            return True
        return method == "POST" and any(
            pattern.fullmatch(path) for pattern in _ANALYST_WRITE_PATTERNS
        )
    return False


class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
    """Authenticate configured API keys, authorize roles, and audit API access.

    The legacy single API key remains an administrator credential for backward
    compatibility. Additional least-privilege credentials are configured by
    key ID with subject, role, and secret.
    """

    def __init__(
        self,
        app: Any,
        *,
        auth_enabled: bool = False,
        api_key: str = "",
        api_keys: dict[str, dict[str, str]] | None = None,
        auth_header_name: str = "X-ArgusProwl-Key",
        audit_log: Any | None = None,
    ) -> None:
        super().__init__(app)
        self._auth_enabled = auth_enabled
        self._config_key = api_key
        self._header_name = auth_header_name
        self._audit_log = audit_log
        self._api_keys: dict[str, AuthPrincipal] = {}
        self._api_secrets: dict[str, str] = {}
        for key_id, definition in (api_keys or {}).items():
            secret = definition.get("secret", "")
            subject = definition.get("subject", key_id)
            role = definition.get("role", "")
            if (
                not isinstance(secret, str) or not secret or not secret.isascii()
                or not isinstance(subject, str) or not subject
                or not isinstance(role, str) or role not in _VALID_ROLES
            ):
                raise ValueError(f"Invalid API key definition for key ID {key_id!r}")
            self._api_secrets[key_id] = secret
            self._api_keys[key_id] = AuthPrincipal(subject=subject, role=role, key_id=key_id)
        if auth_enabled and not (api_key or self._api_keys or os.environ.get("ARGUSPROWL_API_KEY")):
            logger.warning("API auth is enabled but no API key is configured; protected routes fail closed.")

    def _authenticate(self, supplied_key: str | None) -> AuthPrincipal | None:
        if not supplied_key or not supplied_key.isascii():
            return None
        for key_id, secret in self._api_secrets.items():
            if hmac.compare_digest(supplied_key, secret):
                return self._api_keys[key_id]
        legacy_key = self._config_key or os.environ.get("ARGUSPROWL_API_KEY", "")
        if legacy_key and legacy_key.isascii() and hmac.compare_digest(supplied_key, legacy_key):
            return AuthPrincipal(subject="legacy-admin", role="admin", key_id="legacy-admin")
        return None

    def _audit(
        self, *, event_type: str, principal: AuthPrincipal | None, method: str,
        path: str, status_code: int, request_id: str, client_ip: str | None,
    ) -> None:
        if self._audit_log is None:
            return
        self._audit_log.append(
            event_type=event_type,
            actor_id=principal.subject if principal else "anonymous",
            role=principal.role if principal else "anonymous",
            method=method,
            path=path,
            status_code=status_code,
            request_id=request_id,
            client_ip=client_ip,
        )

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        path = request.url.path
        method = request.method.upper()
        if _is_public_path(path, method=method, accept=request.headers.get("accept", "")):
            return await call_next(request)
        if method == "OPTIONS":
            return await call_next(request)

        request_id = str(uuid4())
        client_ip = request.client.host if request.client else None
        principal: AuthPrincipal | None
        if self._auth_enabled:
            principal = self._authenticate(request.headers.get(self._header_name))
            if principal is None:
                try:
                    self._audit(
                        event_type="AUTHENTICATION_FAILED", principal=None, method=method,
                        path=path, status_code=401, request_id=request_id, client_ip=client_ip,
                    )
                except Exception:
                    logger.exception("Could not persist failed-authentication audit event")
                return JSONResponse(
                    status_code=401, content={"detail": "Unauthorized"},
                    headers={"X-Request-ID": request_id},
                )
            if not _role_allows(principal.role, method, path):
                try:
                    self._audit(
                        event_type="AUTHORIZATION_DENIED", principal=principal, method=method,
                        path=path, status_code=403, request_id=request_id, client_ip=client_ip,
                    )
                except Exception:
                    logger.exception("Could not persist authorization-denial audit event")
                return JSONResponse(
                    status_code=403, content={"detail": "Forbidden"},
                    headers={"X-Request-ID": request_id},
                )
        else:
            if path == "/api/v1/audit":
                return JSONResponse(status_code=403, content={"detail": "Forbidden"})
            principal = AuthPrincipal(subject="anonymous", role="anonymous", key_id="anonymous")

        request.state.principal = principal
        request.state.request_id = request_id
        try:
            self._audit(
                event_type="REQUEST_STARTED", principal=principal, method=method,
                path=path, status_code=0, request_id=request_id, client_ip=client_ip,
            )
        except Exception:
            logger.exception("Audit store unavailable; protected request was not executed")
            return JSONResponse(
                status_code=503, content={"detail": "Audit service unavailable"},
                headers={"X-Request-ID": request_id},
            )

        try:
            response = await call_next(request)
        except Exception:
            try:
                self._audit(
                    event_type="REQUEST_FAILED", principal=principal, method=method,
                    path=path, status_code=500, request_id=request_id, client_ip=client_ip,
                )
            except Exception:
                logger.exception("Could not persist request-failure audit event")
            raise

        try:
            self._audit(
                event_type="REQUEST_COMPLETED", principal=principal, method=method,
                path=path, status_code=response.status_code, request_id=request_id,
                client_ip=client_ip,
            )
        except Exception:
            logger.exception("Could not persist request-completion audit event")
        response.headers.setdefault("X-Request-ID", request_id)
        return response
