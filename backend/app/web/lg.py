"""Public looking glass: rate-limited ping/trace/route/status queries dispatched to an agent.

Every query (and its outcome) is logged to the LGQuery table for audit.
"""

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session

from app.auth.session import current_user
from app.db.models import Agent, LGQuery
from app.db.session import get_db
from app.lg.client import AgentClient
from app.lg.validation import validate_query_type, validate_target
from app.web.deps import client_ip, lg_rate_limiter, logger, query_enabled_agents, render

router = APIRouter()


@router.post("/lg", response_class=HTMLResponse)
async def looking_glass(
    request: Request,
    agent_id: int = Form(...),
    query_type: str = Form(...),
    target: str = Form(""),
    db: Session = Depends(get_db),
) -> HTMLResponse:
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
    agents = query_enabled_agents(db).all()
    return render(
        request,
        "index.html",
        {
            "agents": agents,
            "lg_result": result_text,
            "lg_ok": ok,
            "last_query": normalized_query_type,
        },
        user=user,
    )
