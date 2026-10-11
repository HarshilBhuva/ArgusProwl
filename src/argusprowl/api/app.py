"""FastAPI application factory.

Creates the FastAPI application with proper middleware, CORS, and error handling.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

logger = logging.getLogger(__name__)

# Frontend assets are resolved from a fixed set of deployment-specific locations
# instead of relying on the process CWD. Explicit overrides are supported for
# unusual layouts, and tests can still patch this helper directly.
_STATIC_DIR_ENV_VARS = (
    "ARGUSPROWL_STATIC_DIR",
    "TH_API__STATIC_DIR",
)
_CONTAINER_STATIC_DIR = "/app/static"


def _static_dir() -> str:
    for env_var in _STATIC_DIR_ENV_VARS:
        explicit = os.environ.get(env_var)
        if explicit:
            return explicit

    # The unified Docker image copies the compiled frontend to /app/static.
    if os.path.exists(_CONTAINER_STATIC_DIR):
        return _CONTAINER_STATIC_DIR

    # Source-tree layout for local development and direct Python execution.
    try:
        from argusprowl.constants.paths import ProjectPath

        for candidate in (
            Path(ProjectPath.ROOT) / "static",
            Path(ProjectPath.ROOT) / "frontend" / "dist",
        ):
            if candidate.is_dir():
                return str(candidate)
    except Exception:  # pragma: no cover - defensive path-resolution fallback
        pass

    # Preserve prior CWD-based behavior for ad hoc invocations.
    cwd = os.getcwd()
    for candidate in (
        Path(cwd, "static"),
        Path(cwd, "frontend", "dist"),
    ):
        if candidate.is_dir():
            return str(candidate)

    return Path(cwd, "frontend", "dist")


def create_api_app(
    *,
    title: str = "argusprowl API",
    description: str = "argusprowl - Modular Host-Based Threat Detection Platform API",
    version: str = "0.1.0",
    cors_origins: list[str] | None = None,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        title: API title.
        description: API description.
        version: API version.
        cors_origins: List of allowed CORS origins. Empty list disables CORS.

    Returns:
        Configured FastAPI application instance.
    """
    app = FastAPI(
        title=title,
        description=description,
        version=version,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # Configure CORS
    if cors_origins:
        from fastapi.middleware.cors import CORSMiddleware

        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        logger.info("CORS enabled for origins: %s", cors_origins)
    else:
        logger.info("CORS disabled (no origins configured)")

    # Import and include routes
    from argusprowl.api.routes import operational_router, router

    app.include_router(router)
    app.include_router(operational_router)

    # ------------------------------------------------------------------
    # Frontend static-file & SPA routes (unified Docker image mode).
    #
    # In the container, frontend/dist/ is copied to /app/static/, so the
    # app serves the compiled React build from the working directory.
    # For local backend-only development (no frontend build present),
    # these routes are skipped gracefully so the API still boots.
    #
    # IMPORTANT: Registered *after* all API routers so that /api/*,
    # /docs, /redoc, /openapi.json, etc. keep their priority.
    # ------------------------------------------------------------------
    static_dir = _static_dir()
    if os.path.exists(static_dir):
        # Mount the hashed Vite asset bundles under /assets/.
        if os.path.exists(os.path.join(static_dir, "assets")):
            app.mount(
                "/assets", StaticFiles(directory=os.path.join(static_dir, "assets")), name="assets"
            )

        # Capture *static_dir* in the closure so the route body references the
        # same resolved path used at app-creation time (needed when callers
        # monkeypatch _static_dir() between app creation and request handling).
        _idx = os.path.join(static_dir, "index.html")

        # Root: serve the SPA entry point.
        @app.get("/")
        async def serve_index() -> Any:
            if not os.path.exists(_idx):
                raise HTTPException(status_code=404, detail="Frontend index.html not found")
            return FileResponse(_idx)

        # Catch-all SPA fallback for client-side routing.
        # Must NOT intercept backend API or docs paths.
        @app.get("/{full_path:path}")
        async def serve_spa(full_path: str) -> Any:
            # Preserve backend functionality: skip API & docs prefixes.
            reserved = ("api/", "docs", "redoc", "openapi.json", "health")
            if full_path.startswith(reserved):
                return JSONResponse(status_code=404, content={"detail": "Not Found"})
            # Never fall back to index.html for missing static assets.
            if full_path.startswith("assets/"):
                return JSONResponse(status_code=404, content={"detail": "Asset not found"})
            if not os.path.exists(_idx):
                raise HTTPException(status_code=404, detail="Frontend index.html not found")
            return FileResponse(_idx)

    # Custom error handlers
    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle validation errors with structured response."""
        logger.debug("Validation error: %s", exc.errors())
        return JSONResponse(
            status_code=422,
            content={
                "detail": exc.errors(),
                "status_code": 422,
            },
        )

    @app.exception_handler(Exception)
    async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Handle unexpected exceptions without leaking internals."""
        logger.warning("Unhandled exception: %s", exc, exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "detail": "Internal server error",
                "status_code": 500,
            },
        )

    return app
