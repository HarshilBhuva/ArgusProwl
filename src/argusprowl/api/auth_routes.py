"""Browser login endpoints for short-lived HttpOnly API-key sessions."""

from __future__ import annotations

import logging
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from argusprowl.api.auth import ApiKeyAuthService, AuthPrincipal

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class SessionCreateRequest(BaseModel):
    """API key is accepted once and is never returned or persisted by the browser."""

    api_key: str = Field(min_length=1, max_length=4096)


def _audit_login(
    request: Request,
    *,
    event_type: str,
    principal: AuthPrincipal | None,
    status_code: int,
) -> None:
    audit_log = getattr(request.app.state, "audit_log", None)
    if audit_log is None:
        raise RuntimeError("Audit log is unavailable.")
    audit_log.append(
        event_type=event_type,
        actor_id=principal.subject if principal else "anonymous",
        role=principal.role if principal else "anonymous",
        method=request.method,
        path=request.url.path,
        status_code=status_code,
        request_id=str(uuid4()),
        client_ip=request.client.host if request.client else None,
    )


@router.get("/status", summary="Get browser authentication requirements")
async def auth_status(request: Request) -> dict[str, object]:
    service: ApiKeyAuthService = request.app.state.auth_service
    return {
        "auth_enabled": service.auth_enabled,
        "session_ttl_seconds": service.session_ttl_seconds,
    }


@router.get("/me", summary="Get the authenticated browser principal")
async def auth_me(request: Request) -> dict[str, object]:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return {
        "authenticated": True,
        "subject": principal.subject,
        "role": principal.role,
        "key_id": principal.key_id,
    }


@router.post("/session", summary="Create a short-lived browser session")
async def create_session(payload: SessionCreateRequest, request: Request) -> JSONResponse:
    service: ApiKeyAuthService = request.app.state.auth_service
    if not service.auth_enabled:
        raise HTTPException(status_code=409, detail="API authentication is disabled.")
    created = service.create_session(payload.api_key)
    if created is None:
        try:
            _audit_login(
                request,
                event_type="AUTHENTICATION_FAILED",
                principal=None,
                status_code=401,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Audit service unavailable.") from exc
        raise HTTPException(status_code=401, detail="Invalid API key.")
    principal, token = created
    try:
        _audit_login(
            request,
            event_type="AUTHENTICATION_SUCCEEDED",
            principal=principal,
            status_code=200,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail="Audit service unavailable.") from exc

    response = JSONResponse(
        {
            "authenticated": True,
            "subject": principal.subject,
            "role": principal.role,
            "key_id": principal.key_id,
        }
    )
    response.set_cookie(
        key=service.cookie_name,
        value=token,
        max_age=service.session_ttl_seconds,
        path="/api",
        secure=request.url.scheme == "https",
        httponly=True,
        samesite="strict",
    )
    return response


@router.delete("/session", summary="End the current browser session")
async def delete_session(request: Request) -> JSONResponse:
    service: ApiKeyAuthService = request.app.state.auth_service
    principal = service.authenticate_session(request.cookies.get(service.cookie_name))
    if principal is not None:
        try:
            _audit_login(
                request,
                event_type="SESSION_TERMINATED",
                principal=principal,
                status_code=200,
            )
        except Exception:
            # Logout must clear the browser credential even if audit storage is down.
            logger.exception("Could not persist browser session termination event")
    response = JSONResponse({"authenticated": False})
    response.delete_cookie(
        key=service.cookie_name,
        path="/api",
        secure=request.url.scheme == "https",
        httponly=True,
        samesite="strict",
    )
    return response
