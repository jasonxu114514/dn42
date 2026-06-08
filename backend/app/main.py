"""FastAPI application factory for the dn42 autopeer control plane.

Wires the session middleware, static files, and the API + web routers, and runs startup/shutdown
through the lifespan handler: the insecure-secret guard and schema creation.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from http import HTTPStatus

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from app.api.telegram import router as telegram_router
from app.config import get_settings
from app.db.init_db import create_schema
from app.node_ws import router as node_ws_router
from app.web.admin import router as admin_router
from app.web.deps import templates
from app.web.lg import router as lg_router
from app.web.pages import router as pages_router
from app.web.portal import router as portal_router

logger = logging.getLogger("dn42.autopeer")
settings = get_settings()


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    insecure = settings.insecure_default_secrets()
    if insecure and not settings.allow_insecure_defaults:
        raise RuntimeError(
            "Refusing to start with insecure default secrets: "
            + ", ".join(insecure)
            + ". Set strong random values in .env, or pass --allow-http / set "
            "ALLOW_INSECURE_DEFAULTS=1 for local testing only."
        )
    if insecure:
        logger.warning(
            "Starting with insecure default secrets (%s) because insecure defaults are allowed.",
            ", ".join(insecure),
        )
    create_schema()
    yield


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=not settings.allow_insecure_defaults,
    same_site="lax",
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException) -> Response:
    """Render a styled HTML error page for browser requests; keep JSON for everyone else.

    Browsers (Accept: text/html) get ``error.html``; the Telegram API and ``fetch`` calls (which do
    not ask for HTML) fall through to the usual ``{"detail": ...}`` JSON the bot expects.
    瀏覽器收到美化的錯誤頁;Telegram API 與 fetch(不要求 HTML)維持原本的 JSON 回應。
    """
    if "text/html" in request.headers.get("accept", ""):
        try:
            title = HTTPStatus(exc.status_code).phrase
        except ValueError:
            title = "Error"
        return templates.TemplateResponse(
            request=request,
            name="error.html",
            context={
                "request": request,
                "settings": settings,
                "code": exc.status_code,
                "title": title,
                "detail": exc.detail,
            },
            status_code=exc.status_code,
        )
    return JSONResponse(
        {"detail": exc.detail}, status_code=exc.status_code, headers=getattr(exc, "headers", None)
    )


app.include_router(telegram_router)
app.include_router(node_ws_router)
app.include_router(pages_router)
app.include_router(portal_router)
app.include_router(admin_router)
app.include_router(lg_router)
