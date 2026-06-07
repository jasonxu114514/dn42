"""Public looking glass: rate-limited ping/trace/route/status queries dispatched to an agent.

Every query (and its outcome) is logged to the LGQuery table for audit. Browsers submitting the
form get the full page back; the in-page ``fetch`` (header ``X-Requested-With: fetch``) gets a small
JSON payload so the result can be swapped in without a reload.
"""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from sqlalchemy.orm import Session

from app.auth.session import current_user
from app.db.models import Agent, LGQuery
from app.db.session import get_db
from app.lg.client import AgentClient
from app.lg.validation import validate_query_type, validate_target
from app.web.deps import client_ip, lg_rate_limiter, logger, query_enabled_agents, render

router = APIRouter()


@router.get("/lg", response_class=HTMLResponse)
def looking_glass_page(request: Request, db: Session = Depends(get_db)) -> HTMLResponse:
    """Render the looking-glass query form (the POST handler below runs the query)."""
    agents = query_enabled_agents(db).all()
    return render(
        request, "lg.html", {"agents": agents}, user=current_user(request, db), active="lg"
    )


@router.post("/lg", response_class=HTMLResponse)
async def looking_glass(
    request: Request,
    agent_id: int = Form(...),
    query_type: str = Form(...),
    target: str = Form(""),
    db: Session = Depends(get_db),
) -> Response:
    if not lg_rate_limiter.allow(client_ip(request)):
        raise HTTPException(
            status_code=429,
            detail="Too many looking glass queries. Please wait a moment and try again.",
        )
    agent = query_enabled_agents(db).filter(Agent.id == agent_id).one_or_none()
    if agent is None:
        raise HTTPException(status_code=400, detail="Unknown or disabled agent")
    result_text = ""
    ok = False
    normalized_query_type = query_type
    normalized_target = target.strip()
    try:
        normalized_query_type = validate_query_type(query_type)
        normalized_target = validate_target(normalized_query_type, target)
    except ValueError as exc:
        result_text = str(exc)
    else:
        try:
            result = await AgentClient().query(agent, normalized_query_type, normalized_target)
            ok = bool(result.get("ok", False))
            result_text = str(result.get("output", result))
        except ValueError as exc:
            result_text = str(exc)
        except Exception as exc:
            logger.warning(
                "Looking glass query failed (agent=%s, type=%s): %s",
                agent.name,
                normalized_query_type,
                exc,
            )
            result_text = "Query failed: could not reach the looking glass agent."
    user = current_user(request, db)
    db.add(
        LGQuery(
            user_id=user.id if user else None,
            agent_id=agent.id,
            query_type=normalized_query_type,
            target=normalized_target,
            ok=ok,
            result=result_text,
        )
    )
    db.commit()

    # In-page fetch: return just the outcome as JSON so app.js can swap it in without a reload.
    if request.headers.get("x-requested-with", "").lower() == "fetch":
        return JSONResponse({"ok": ok, "output": result_text, "query_type": normalized_query_type})

    agents = query_enabled_agents(db).all()
    return render(
        request,
        "lg.html",
        {
            "agents": agents,
            "lg_result": result_text,
            "lg_ok": ok,
            "last_query": normalized_query_type,
            "last_target": normalized_target,
        },
        user=user,
        active="lg",
    )
