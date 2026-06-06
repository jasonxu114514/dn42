"""FastAPI application factory for the dn42 autopeer control plane.

Wires the session middleware, static files, and the API + web routers, and runs startup/shutdown
through the lifespan handler: the insecure-secret guard, schema creation, default seeding, and
teardown of the pooled looking-glass HTTP client.
"""

import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.api.telegram import router as telegram_router
from app.config import get_settings
from app.db.init_db import create_schema, seed_defaults
from app.db.session import SessionLocal
from app.lg.client import aclose_shared_client
from app.web.admin import router as admin_router
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
    db = SessionLocal()
    try:
        seed_defaults(db, settings)
    finally:
        db.close()
    yield
    await aclose_shared_client()


app = FastAPI(title=settings.app_name, lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=settings.session_secret,
    https_only=not settings.allow_insecure_defaults,
    same_site="lax",
)
app.mount("/static", StaticFiles(directory="app/static"), name="static")
app.include_router(telegram_router)
app.include_router(pages_router)
app.include_router(portal_router)
app.include_router(admin_router)
app.include_router(lg_router)
