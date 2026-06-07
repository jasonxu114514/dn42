"""Shared building blocks for the web (HTML) routes.

Holds the process-wide configured objects (settings, Jinja templates, the looking-glass rate
limiter) and the small helpers every router needs: ``render`` for template responses,
``query_enabled_agents`` for the common agent query, ``client_ip`` for rate-limit identity, the
``flash`` one-shot session messages, the ``Pagination`` helper, and the ``require_admin`` FastAPI
dependency that replaces the repeated admin-auth checks.
"""

import logging
import math
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from app.auth.session import current_user
from app.config import get_settings
from app.db.models import Agent, User
from app.db.session import get_db
from app.lg.ratelimit import SlidingWindowRateLimiter

logger = logging.getLogger("dn42.autopeer")
settings = get_settings()
templates = Jinja2Templates(directory="app/templates")
lg_rate_limiter = SlidingWindowRateLimiter(settings.lg_rate_limit, settings.lg_rate_window_seconds)

# Session key holding pending one-shot flash messages until the next rendered page drains them.
_FLASH_KEY = "_flash"


def flash(request: Request, message: str, category: str = "info") -> None:
    """Queue a one-shot message shown on the next rendered page, then discarded.

    Used by browser form routes to report a validation error (then redirect back) instead of
    dumping FastAPI's raw ``{"detail": ...}`` JSON. ``category`` is one of info/success/error and
    only selects the banner style. 表單錯誤以 flash 顯示後即丟棄,取代原本的 JSON 錯誤回應。
    """
    request.session.setdefault(_FLASH_KEY, []).append({"category": category, "message": message})


def render(
    request: Request,
    name: str,
    context: dict | None = None,
    user: User | None = None,
    active: str | None = None,
) -> HTMLResponse:
    """Render ``name`` with the base context (request, settings, user, active nav, flashes).

    ``active`` is the current top-nav key (``lg``/``portal``/``admin``) for highlighting. Pending
    flashes are popped from the session here so they show exactly once.
    """
    base = {
        "request": request,
        "settings": settings,
        "user": user,
        "active": active,
        "flashes": request.session.pop(_FLASH_KEY, []),
    }
    if context:
        base.update(context)
    return templates.TemplateResponse(request=request, name=name, context=base)


def query_enabled_agents(db: Session):
    """Query of enabled agents ordered by name. Returns the query so callers can refine it."""
    return db.query(Agent).filter(Agent.enabled.is_(True)).order_by(Agent.name)


def client_ip(request: Request) -> str:
    """Best-effort client identity for rate limiting.

    Uses request.client.host by default. Set FORWARDED_IP_HEADER (e.g. ``X-Forwarded-For``)
    only when running behind a trusted reverse proxy that sets it, otherwise every request
    would share one bucket (the proxy IP).
    """
    header = settings.forwarded_ip_header.strip()
    if header:
        value = request.headers.get(header, "")
        if value:
            return value.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def require_admin(request: Request, db: Session = Depends(get_db)) -> User:
    """FastAPI dependency: return the current admin user, or raise 403.

    ``get_db`` is request-cached, so declaring this dependency does not open a second session;
    a route can keep its own ``db: Session = Depends(get_db)`` and share the same one.
    """
    user = current_user(request, db)
    if user is None or not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin access required")
    return user


@dataclass
class Pagination:
    """Page math for list views. Clamps ``page`` into ``[1, pages]`` against ``total``.

    The route supplies the raw ``page`` query param and the row ``total``; the clamped ``page`` and
    ``offset`` then drive the ``LIMIT``/``OFFSET`` query, and the template uses ``pages``/
    ``has_prev``/``has_next`` to draw the pager.
    """

    page: int
    per_page: int
    total: int

    def __post_init__(self) -> None:
        self.page = max(1, min(self.page, self.pages))

    @property
    def pages(self) -> int:
        return max(1, math.ceil(self.total / self.per_page))

    @property
    def offset(self) -> int:
        return (self.page - 1) * self.per_page

    @property
    def has_prev(self) -> bool:
        return self.page > 1

    @property
    def has_next(self) -> bool:
        return self.page < self.pages
