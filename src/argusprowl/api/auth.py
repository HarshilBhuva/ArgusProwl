"""API-key authentication and role-based authorization middleware."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit
from uuid import uuid4

from argusprowl.api.auth_store import AuthAttemptLimiter

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger(__name__)

_SESSION_COOKIE_NAME = "argusprowl_session"
_SESSION_TTL_SECONDS = 3600

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
    normalized = path.rstrip("/") or "/"
    if normalized == "/api/v1/auth/session" and method in {"POST", "DELETE"}:
        return True
    if normalized == "/api/v1/auth/status" and method in {"GET", "HEAD"}:
        return True
    if method not in {"GET", "HEAD"}:
        return False
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



def _request_scheme(request: Request) -> str:
    """Return the external scheme, honoring the reverse proxy's forwarded protocol."""
    forwarded_proto = request.headers.get("x-forwarded-proto", "")
    return (
        forwarded_proto.split(",", 1)[0].strip().lower()
        if forwarded_proto
        else request.url.scheme.lower()
    )


def _request_is_secure(request: Request) -> bool:
    """Determine whether the browser-facing connection uses HTTPS."""
    return _request_scheme(request) == "https"


def _origin_matches_request(request: Request, origin: str | None) -> bool:
    """Validate a browser Origin against the externally visible request origin."""
    if not origin or origin == "null":
        return False
    try:
        origin_parts = urlsplit(origin)
        scheme = _request_scheme(request)
        host = request.headers.get("host", request.url.netloc).split(",", 1)[0].strip()
        return (
            not origin_parts.path
            and not origin_parts.query
            and not origin_parts.fragment
            and origin_parts.scheme.lower() == scheme.lower()
            and origin_parts.netloc.lower() == host.lower()
        )
    except ValueError:
        return False


def _parse_key_expiry(value: Any) -> datetime | None:
    """Parse an optional timezone-aware ISO-8601 expiry timestamp."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValueError("API key expires_at must be a non-empty ISO-8601 timestamp.")
    normalized = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError("API key expires_at must be a valid ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("API key expires_at must include a timezone offset.")
    return parsed.astimezone(UTC)


class ApiKeyAuthService:
    """Validate API keys and issue short-lived, stateless browser sessions.

    Session tokens are HMAC-signed with the matching API key secret. Every
    request revalidates the key's current enabled/expiry state, so rotating or
    revoking a credential invalidates sessions signed by that credential.
    """

    cookie_name = _SESSION_COOKIE_NAME
    session_ttl_seconds = _SESSION_TTL_SECONDS

    def __init__(
        self,
        *,
        auth_enabled: bool,
        api_key: str = "",
        api_keys: dict[str, dict[str, Any]] | None = None,
        revocation_store: Any | None = None,
        attempt_limiter: AuthAttemptLimiter | None = None,
    ) -> None:
        self.auth_enabled = auth_enabled
        self._revocation_store = revocation_store
        self._attempt_limiter = attempt_limiter or AuthAttemptLimiter()
        self._credentials: dict[str, tuple[AuthPrincipal, str, bool, datetime | None]] = {}
        for key_id, definition in (api_keys or {}).items():
            secret = definition.get("secret", "")
            subject = definition.get("subject", key_id)
            role = definition.get("role", "")
            enabled = definition.get("enabled", True)
            expires_at = _parse_key_expiry(definition.get("expires_at"))
            if (
                not isinstance(key_id, str) or not key_id or key_id == "legacy-admin"
                or not isinstance(secret, str) or not secret or not secret.isascii()
                or not isinstance(subject, str) or not subject
                or not isinstance(role, str) or role not in _VALID_ROLES
                or not isinstance(enabled, bool)
            ):
                raise ValueError(f"Invalid API key definition for key ID {key_id!r}")
            self._credentials[key_id] = (
                AuthPrincipal(subject=subject, role=role, key_id=key_id),
                secret,
                enabled,
                expires_at,
            )
        legacy_key = api_key or os.environ.get("ARGUSPROWL_API_KEY", "")
        if legacy_key:
            if not isinstance(legacy_key, str) or not legacy_key.isascii():
                raise ValueError("Legacy API key must contain ASCII characters.")
            self._credentials["legacy-admin"] = (
                AuthPrincipal(subject="legacy-admin", role="admin", key_id="legacy-admin"),
                legacy_key,
                True,
                None,
            )

    @property
    def has_credentials(self) -> bool:
        return bool(self._credentials)

    def _active_credential(
        self, key_id: str, now: datetime
    ) -> tuple[AuthPrincipal, str] | None:
        credential = self._credentials.get(key_id)
        if credential is None:
            return None
        principal, secret, enabled, expires_at = credential
        if not enabled or (expires_at is not None and now >= expires_at):
            return None
        if self._revocation_store is not None:
            try:
                if self._revocation_store.is_revoked(key_id):
                    return None
            except Exception:
                logger.exception("Credential revocation store unavailable; rejecting credential")
                return None
        return principal, secret

    def authenticate_key(self, supplied_key: str | None) -> AuthPrincipal | None:
        if not supplied_key or not supplied_key.isascii():
            return None
        now = datetime.now(UTC)
        for key_id, (_principal, secret, _enabled, _expires_at) in self._credentials.items():
            if hmac.compare_digest(supplied_key, secret):
                active = self._active_credential(key_id, now)
                return active[0] if active is not None else None
        return None

    def revoke_key(self, key_id: str, *, revoked_by: str) -> bool:
        """Persistently revoke a configured key, including its active sessions."""
        if key_id not in self._credentials or self._revocation_store is None:
            return False
        self._revocation_store.revoke(key_id, revoked_by=revoked_by)
        return True

    def is_rate_limited(self, client_ip: str | None) -> bool:
        """Return whether this client is currently locked out after failed auth."""
        return self._attempt_limiter.is_blocked(client_ip)

    def retry_after(self, client_ip: str | None) -> int:
        """Return the remaining lockout in seconds, rounded up."""
        return self._attempt_limiter.retry_after(client_ip)

    def record_auth_failure(self, client_ip: str | None) -> bool:
        """Record a failed authentication and report whether it triggered lockout."""
        return self._attempt_limiter.record_failure(client_ip)

    def record_auth_success(self, client_ip: str | None) -> None:
        """Clear failed-authentication history after a successful login."""
        self._attempt_limiter.record_success(client_ip)

    @staticmethod
    def _encode_segment(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode_segment(value: str) -> bytes:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    def create_session(self, supplied_key: str | None) -> tuple[AuthPrincipal, str] | None:
        """Validate a credential and return its principal plus signed session token."""
        if not self.auth_enabled:
            return None
        principal = self.authenticate_key(supplied_key)
        if principal is None:
            return None
        credential = self._active_credential(principal.key_id, datetime.now(UTC))
        if credential is None:
            return None
        now = int(datetime.now(UTC).timestamp())
        payload = {
            "kid": principal.key_id,
            "sub": principal.subject,
            "role": principal.role,
            "jti": uuid4().hex,
            "iat": now,
            "exp": now + self.session_ttl_seconds,
        }
        encoded_payload = self._encode_segment(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )
        signature = hmac.new(
            credential[1].encode("ascii"), encoded_payload.encode("ascii"), hashlib.sha256
        ).digest()
        return principal, f"{encoded_payload}.{self._encode_segment(signature)}"

    def authenticate_session(self, token: str | None) -> AuthPrincipal | None:
        """Validate signature, expiry, and current credential state for a session."""
        if not self.auth_enabled or not token or len(token) > 4096:
            return None
        try:
            encoded_payload, encoded_signature = token.split(".", 1)
            payload = json.loads(self._decode_segment(encoded_payload))
            signature = self._decode_segment(encoded_signature)
            key_id = payload["kid"]
            subject = payload["sub"]
            role = payload["role"]
            token_id = payload["jti"]
            issued_at = payload["iat"]
            expires_at = payload["exp"]
            if (
                not isinstance(key_id, str)
                or not isinstance(subject, str)
                or not isinstance(role, str)
                or not isinstance(token_id, str)
                or not token_id
                or not isinstance(issued_at, int)
                or isinstance(issued_at, bool)
                or not isinstance(expires_at, int)
                or isinstance(expires_at, bool)
            ):
                return None
            now = int(datetime.now(UTC).timestamp())
            if (
                issued_at > now + 60
                or expires_at <= now
                or expires_at <= issued_at
                or expires_at - issued_at > self.session_ttl_seconds
            ):
                return None
            credential = self._active_credential(key_id, datetime.now(UTC))
            if credential is None:
                return None
            principal, secret = credential
            expected = hmac.new(
                secret.encode("ascii"), encoded_payload.encode("ascii"), hashlib.sha256
            ).digest()
            if not hmac.compare_digest(signature, expected):
                return None
            if principal.subject != subject or principal.role != role:
                return None
            return principal
        except (KeyError, TypeError, ValueError):
            return None


def _role_allows(role: str, method: str, path: str) -> bool:
    """Apply deny-by-default authorization for protected API operations."""
    method = method.upper()
    if path == "/api/v1/audit" or path.startswith("/api/v1/audit/"):
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
        api_keys: dict[str, dict[str, Any]] | None = None,
        auth_header_name: str = "X-ArgusProwl-Key",
        audit_log: Any | None = None,
        auth_service: ApiKeyAuthService | None = None,
    ) -> None:
        super().__init__(app)
        self._auth_service = auth_service or ApiKeyAuthService(
            auth_enabled=auth_enabled,
            api_key=api_key,
            api_keys=api_keys,
        )
        self._auth_enabled = self._auth_service.auth_enabled
        self._header_name = auth_header_name
        self._audit_log = audit_log
        if self._auth_enabled and not self._auth_service.has_credentials:
            logger.warning(
                "API auth is enabled but no API key is configured; protected routes fail closed."
            )

    def _authenticate(self, supplied_key: str | None) -> AuthPrincipal | None:
        return self._auth_service.authenticate_key(supplied_key)

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
        authenticated_via_session = False
        if self._auth_enabled:
            if self._auth_service.is_rate_limited(client_ip):
                retry_after = self._auth_service.retry_after(client_ip)
                try:
                    self._audit(
                        event_type="AUTH_RATE_LIMITED", principal=None, method=method,
                        path=path, status_code=429, request_id=request_id, client_ip=client_ip,
                    )
                except Exception:
                    logger.exception("Could not persist rate-limit audit event")
                return JSONResponse(
                    status_code=429, content={"detail": "Too many authentication attempts"},
                    headers={"X-Request-ID": request_id, "Retry-After": str(retry_after)},
                )
            principal = self._authenticate(request.headers.get(self._header_name))
            if principal is None:
                principal = self._auth_service.authenticate_session(
                    request.cookies.get(self._auth_service.cookie_name)
                )
                authenticated_via_session = principal is not None
            if principal is None:
                locked = self._auth_service.record_auth_failure(client_ip)
                status_code = 429 if locked else 401
                event_type = "AUTH_RATE_LIMITED" if locked else "AUTHENTICATION_FAILED"
                try:
                    self._audit(
                        event_type=event_type, principal=None, method=method,
                        path=path, status_code=status_code, request_id=request_id,
                        client_ip=client_ip,
                    )
                except Exception:
                    logger.exception("Could not persist failed-authentication audit event")
                headers = {"X-Request-ID": request_id}
                if locked:
                    headers["Retry-After"] = str(self._auth_service.retry_after(client_ip))
                return JSONResponse(
                    status_code=status_code,
                    content={"detail": "Too many authentication attempts" if locked else "Unauthorized"},
                    headers=headers,
                )
            self._auth_service.record_auth_success(client_ip)
            if (
                authenticated_via_session
                and method not in {"GET", "HEAD", "OPTIONS"}
                and not _origin_matches_request(request, request.headers.get("origin"))
            ):
                try:
                    self._audit(
                        event_type="CSRF_ORIGIN_REJECTED", principal=principal,
                        method=method, path=path, status_code=403,
                        request_id=request_id, client_ip=client_ip,
                    )
                except Exception:
                    logger.exception("Could not persist CSRF rejection audit event")
                return JSONResponse(
                    status_code=403, content={"detail": "Forbidden"},
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
            if path == "/api/v1/audit" or path.startswith("/api/v1/audit/"):
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
