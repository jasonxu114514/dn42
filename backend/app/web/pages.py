"""Public pages and auth callbacks: home, login/logout, Kioubit + Telegram auth."""

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from app.agent_ws import agent_runtime_context
from app.auth.kioubit import KioubitAuthError, KioubitVerifier
from app.auth.service import consume_challenge, create_challenge, upsert_user_from_kioubit
from app.auth.session import current_user, login_user, logout_user
from app.db.session import get_db
from app.web.deps import query_enabled_agents, render, settings

router = APIRouter()


@router.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    """Landing page: introduce the network and show the live status of every enabled PoP."""
    agents = query_enabled_agents(db).all()
    runtime = agent_runtime_context(agents)
    agents_online = sum(1 for item in runtime.values() if item["online"])
    return render(
        request,
        "home.html",
        {"agents": agents, "agent_runtime": runtime, "agents_online": agents_online},
        user=current_user(request, db),
        active="home",
    )


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    challenge = create_challenge(db, purpose="web")
    return render(
        request,
        "login.html",
        {
            "return_url": f"{settings.base_url}/auth/kioubit/callback",
            "token": challenge.token,
        },
        user=current_user(request, db),
    )


@router.get("/logout")
def logout(request: Request) -> RedirectResponse:
    logout_user(request)
    return RedirectResponse("/", status_code=303)


@router.get("/auth/kioubit/callback")
def kioubit_callback(
    request: Request,
    params: str,
    signature: str,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    verifier = KioubitVerifier(settings.kioubit_public_key_path, settings.auth_domain)
    try:
        data = verifier.verify(params=params, signature=signature)
        consume_challenge(db, data.get("user_token", ""), purpose="web")
        user = upsert_user_from_kioubit(db, data, settings)
    except (KioubitAuthError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    login_user(request, user)
    return RedirectResponse("/portal", status_code=303)


@router.get("/telegram/auth", response_class=HTMLResponse)
def telegram_auth_page(
    request: Request,
    token: str,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    return render(
        request,
        "telegram_auth.html",
        {
            "return_url": f"{settings.base_url}/telegram/auth?token={token}",
            "token": token,
        },
        user=current_user(request, db),
    )
