"""API authentication middleware.

A shared-secret API key is suitable for a single-node deployment. The
allowlist is deliberately narrow: API paths are never made public by a file
extension or a similar-looking path. Browser navigation to non-API SPA routes
may remain public; sensitive endpoints must live under /api/.
"""

from __future__ import annotations

import hmac
import logging
import os
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger(__name__)

# Exact public endpoints. Keep API exemptions exact to avoid prefix bypasses.
_PUBLIC_EXACT_PATHS = frozenset(
    {
        "/",
        "/health",
        "/api/v1/health",
        "/docs",
        "/docs/oauth2-redirect",
        "/redoc",
        "/openapi.json",
        "/favicon.ico",
        "/robots.txt",
        "/manifest.webmanifest",
    }
)
_PUBLIC_PREFIXES = ("/assets/",)


def _is_public_path(path: str, *, method: str = "GET", accept: str = "") -> bool:
    """Return whether a request path may bypass API-key authentication.

    API routes are checked first and only the exact health route is exempt.
    Static asset exemptions are restricted to the dedicated assets mount.
    Non-API HTML navigation is allowed for client-side SPA routes so refreshing
    a frontend page works without weakening API protection.
    """
    method = method.upper()
    if method not in {"GET", "HEAD"}:
        return False

    normalized = path.rstrip("/") or "/"
    if normalized.startswith("/api/"):
        return normalized == "/api/v1/health"

    if normalized in _PUBLIC_EXACT_PATHS:
        return True
    if any(normalized.startswith(prefix) for prefix in _PUBLIC_PREFIXES):
        return True

    # Do not let near-miss operational/docs paths fall through as SPA routes.
    reserved_prefixes = ("/health/", "/docs/", "/redoc/", "/openapi", "/metrics", "/internal/")
    if normalized.startswith(reserved_prefixes):
        return False

    # The frontend's history fallback serves client-side routes as HTML. Only
    # browser navigation is public; API-like paths and static extensions above
    # do not become public merely because of their suffix.
    return "text/html" in accept.lower() and "." not in normalized.rsplit("/", 1)[-1]


class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
    """Enforce a shared-secret API key on non-public routes.

    The effective key is resolved in this order:
      1. Explicit value supplied by application configuration.
      2. ARGUSPROWL_API_KEY environment variable.

    The secret is never written to log messages.
    """

    def __init__(
        self,
        app: Awaitable[Callable[[Request], JSONResponse]],
        *,
        auth_enabled: bool = False,
        api_key: str = "",
        auth_header_name: str = "X-ArgusProwl-Key",
    ) -> None:
        super().__init__(app)
        self._auth_enabled = auth_enabled
        self._config_key = api_key
        self._header_name = auth_header_name
        if auth_enabled and not api_key:
            logger.warning(
                "API auth is enabled but no key is configured "
                "(neither in config nor ARGUSPROWL_API_KEY env var). "
                "Non-public routes will be blocked."
            )

    def _resolve_key(self) -> str:
        """Resolve the effective API key at request time."""
        if self._config_key:
            return self._config_key
        return os.environ.get("ARGUSPROWL_API_KEY", "")

    async def dispatch(
        self, request: Request, call_next: Callable[[Request], Awaitable]
    ) -> JSONResponse:
        """Enforce the shared secret on non-public routes."""
        if not self._auth_enabled or _is_public_path(
            request.url.path,
            method=request.method,
            accept=request.headers.get("accept", ""),
        ):
            return await call_next(request)  # type: ignore[return-value]

        effective_key = self._resolve_key()
        if not effective_key:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        supplied_key = request.headers.get(self._header_name)
        if supplied_key is None or not hmac.compare_digest(supplied_key, effective_key):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        return await call_next(request)  # type: ignore[return-value]
