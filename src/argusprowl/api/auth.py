"""API authentication middleware.

Shared-secret API key mechanism appropriate for a single-node alpha deployment.
Implemented as a FastAPI/Starlette middleware so it applies uniformly to all
sensitive routes — including ones registered by included routers whose
dependencies FastAPI does not propagate from ``router.dependencies``.

No JWT, no OAuth — a single middleware covers the entire API surface.

The secret value is never written to log messages.
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

# Public paths that never require authentication, regardless of auth settings.
PUBLIC_PATH_PREFIXES: tuple[str, ...] = (
    "/health",
    "/api/v1/health",
    "/",
    "/assets/",
    "/docs",
    "/redoc",
    "/openapi.json",
)

_PUBLIC_FILE_EXTENSIONS: tuple[str, ...] = (".js", ".css", ".html", ".svg", ".ico")


def _is_public_path(path: str) -> bool:
    """Return True when *path* is exempt from authentication."""
    if path in PUBLIC_PATH_PREFIXES:
        return True
    lower = path.lower()
    for prefix in PUBLIC_PATH_PREFIXES:
        if len(prefix) <= 1:
            continue
        if lower.startswith(prefix):
            return True
    for ext in _PUBLIC_FILE_EXTENSIONS:
        if lower.endswith(ext):
            return True
    return "favicon" in lower


class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that enforces a shared-secret API key on protected routes.

    Args:
        app: The next ASGI application in the stack.
        auth_enabled: When False, all requests are passed through without check.
        api_key: The expected secret. Resolved in this order:
            1. The *api_key* value passed to this middleware instance.
            2. The ``ARGUSPROWL_API_KEY`` environment variable.
        auth_header_name: The HTTP header name carrying the key (default
            ``X-ArgusProwl-Key``).
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
        self._config_key = api_key  # explicit key from config (may be empty)
        self._header_name = auth_header_name
        if auth_enabled and not api_key:
            logger.warning(
                "API auth is enabled but no key is configured "
                "(neither in config nor ARGUSPROWL_API_KEY env var). "
                "Non-public routes will be blocked."
            )

    def _resolve_key(self) -> str:
        """Resolve the effective API key at request time.

        Explicit config value wins; otherwise falls back to the
        ``ARGUSPROWL_API_KEY`` environment variable.
        """
        if self._config_key:
            return self._config_key
        return os.environ.get("ARGUSPROWL_API_KEY", "")

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable]) -> JSONResponse:
        """Enforce the shared secret on non-public routes."""
        if not self._auth_enabled or _is_public_path(request.url.path):
            response = await call_next(request)
            return response  # type: ignore[return-value]

        effective_key = self._resolve_key()
        if not effective_key:
            # Fail-closed: no key available anywhere means deny non-public routes.
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        key = request.headers.get(self._header_name)
        if key is None:
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        # Constant-time comparison to prevent timing attacks.
        if not hmac.compare_digest(key, effective_key):
            return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        return await call_next(request)  # type: ignore[return-value]
