"""Browser login endpoints for short-lived HttpOnly API-key sessions."""

from __future__ import annotations

import ipaddress
import logging
from uuid import uuid4

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from argusprowl.api.auth import (
    ApiKeyAuthService,
    AuthPrincipal,
    _origin_matches_request,
    _request_is_secure,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["Authentication"])


class SessionCreateRequest(BaseModel):
    """API key is accepted once and is never returned or persisted by the browser."""

    api_key: str = Field(min_length=1, max_length=4096)


class BootstrapAdminRequest(BaseModel):
    """One-time local setup request."""

    bootstrap_token: str = Field(min_length=32, max_length=256)
    subject: str = Field(min_length=1, max_length=128)


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


@router.post("/bootstrap", summary="Create the first administrator credential")
async def bootstrap_admin(payload: BootstrapAdminRequest, request: Request) -> JSONResponse:
    """Consume a one-time local token and create a persistent administrator API key."""
    service: ApiKeyAuthService = request.app.state.auth_service
    store = request.app.state.bootstrap_store
    if not service.auth_enabled:
        raise HTTPException(status_code=409, detail="Enable API authentication before setup.")
    if service.has_credentials:
        raise HTTPException(status_code=409, detail="Administrator bootstrap is already complete.")
    client_ip = request.client.host if request.client else ""
    try:
        is_loopback = ipaddress.ip_address(client_ip).is_loopback
    except ValueError:
        is_loopback = False
    if not is_loopback:
        raise HTTPException(status_code=403, detail="Bootstrap is available only over loopback.")
    origin = request.headers.get("origin")
    if origin is not None and not _origin_matches_request(request, origin):
        raise HTTPException(status_code=403, detail="Forbidden")
    if service.is_rate_limited(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many bootstrap attempts",
            headers={"Retry-After": str(service.retry_after(client_ip))},
        )

    created = store.create_admin(payload.bootstrap_token, payload.subject.strip())
    if created is None:
        locked = service.record_auth_failure(client_ip)
        status_code = 429 if locked else 401
        try:
            _audit_login(
                request,
                event_type="ADMIN_BOOTSTRAP_FAILED",
                principal=None,
                status_code=status_code,
            )
        except Exception:
            logger.exception("Could not persist failed bootstrap audit event")
        headers = {"Retry-After": str(service.retry_after(client_ip))} if locked else None
        raise HTTPException(
            status_code=status_code,
            detail="Invalid or already-consumed bootstrap token.",
            headers=headers,
        )

    key_id, api_key = created
    principal = service.register_credential(
        key_id,
        {
            "secret": api_key,
            "subject": payload.subject.strip(),
            "role": "admin",
            "enabled": True,
        },
    )
    service.record_auth_success(client_ip)
    try:
        _audit_login(
            request,
            event_type="ADMIN_BOOTSTRAPPED",
            principal=principal,
            status_code=201,
        )
    except Exception as exc:
        logger.exception("Administrator was bootstrapped but its audit event could not be persisted")
        raise HTTPException(status_code=503, detail="Audit service unavailable.") from exc

    return JSONResponse(
        {
            "created": True,
            "key_id": key_id,
            "subject": principal.subject,
            "role": principal.role,
            "api_key": api_key,
            "message": "Store this API key securely. It will not be shown again.",
        },
        status_code=201,
        headers={"Cache-Control": "no-store", "Pragma": "no-cache"},
    )


@router.get("/status", summary="Get browser authentication requirements")
async def auth_status(request: Request) -> JSONResponse:
    service: ApiKeyAuthService = request.app.state.auth_service
    return JSONResponse(
        {
            "auth_enabled": service.auth_enabled,
            "bootstrap_required": service.auth_enabled and not service.has_credentials,
            "session_ttl_seconds": service.session_ttl_seconds,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.get("/me", summary="Get the authenticated browser principal")
async def auth_me(request: Request) -> JSONResponse:
    principal = getattr(request.state, "principal", None)
    if principal is None:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return JSONResponse(
        {
            "authenticated": True,
            "subject": principal.subject,
            "role": principal.role,
            "key_id": principal.key_id,
        },
        headers={"Cache-Control": "no-store"},
    )


@router.post("/session", summary="Create a short-lived browser session")
async def create_session(payload: SessionCreateRequest, request: Request) -> JSONResponse:
    service: ApiKeyAuthService = request.app.state.auth_service
    if not service.auth_enabled:
        raise HTTPException(status_code=409, detail="API authentication is disabled.")
    client_ip = request.client.host if request.client else None
    if service.is_rate_limited(client_ip):
        retry_after = service.retry_after(client_ip)
        try:
            _audit_login(
                request,
                event_type="AUTH_RATE_LIMITED",
                principal=None,
                status_code=429,
            )
        except Exception:
            logger.exception("Could not persist rate-limit audit event")
        raise HTTPException(
            status_code=429,
            detail="Too many authentication attempts",
            headers={"Retry-After": str(retry_after)},
        )
    if not _origin_matches_request(request, request.headers.get("origin")):
        try:
            _audit_login(
                request,
                event_type="AUTHENTICATION_ORIGIN_REJECTED",
                principal=None,
                status_code=403,
            )
        except Exception:
            logger.exception("Could not persist rejected browser login origin")
        raise HTTPException(status_code=403, detail="Forbidden")
    created = service.create_session(payload.api_key)
    if created is None:
        locked = service.record_auth_failure(client_ip)
        status_code = 429 if locked else 401
        event_type = "AUTH_RATE_LIMITED" if locked else "AUTHENTICATION_FAILED"
        try:
            _audit_login(
                request,
                event_type=event_type,
                principal=None,
                status_code=status_code,
            )
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Audit service unavailable.") from exc
        headers = {"Retry-After": str(service.retry_after(client_ip))} if locked else None
        raise HTTPException(
            status_code=status_code,
            detail="Too many authentication attempts" if locked else "Invalid API key.",
            headers=headers,
        )
    service.record_auth_success(client_ip)
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
        },
        headers={"Cache-Control": "no-store"},
    )
    response.set_cookie(
        key=service.cookie_name,
        value=token,
        max_age=service.session_ttl_seconds,
        path="/api",
        secure=_request_is_secure(request),
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
    response = JSONResponse(
        {"authenticated": False},
        headers={"Cache-Control": "no-store"},
    )
    response.delete_cookie(
        key=service.cookie_name,
        path="/api",
        secure=request.url.scheme == "https",
        httponly=True,
        samesite="strict",
    )
    return response


@router.post("/keys/{key_id}/revoke", summary="Revoke an API key")
async def revoke_api_key(key_id: str, request: Request) -> JSONResponse:
    """Persistently revoke a configured API key and invalidate its sessions."""
    service: ApiKeyAuthService = request.app.state.auth_service
    principal = getattr(request.state, "principal", None)
    if not service.auth_enabled or principal is None or principal.role != "admin":
        raise HTTPException(status_code=403, detail="Forbidden")
    if not service.revoke_key(key_id, revoked_by=principal.subject):
        raise HTTPException(status_code=404, detail="API key not found")
    try:
        _audit_login(
            request,
            event_type="API_KEY_REVOKED",
            principal=principal,
            status_code=200,
        )
    except Exception as exc:
        logger.exception("API key was revoked but its audit event could not be persisted")
        raise HTTPException(status_code=503, detail="Audit service unavailable.") from exc
    return JSONResponse(
        {"revoked": True, "key_id": key_id},
        headers={"Cache-Control": "no-store"},
    )
