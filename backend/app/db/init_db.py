from sqlalchemy import inspect, text
from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import Node
from app.db.session import Base, engine


def create_schema() -> None:
    Base.metadata.create_all(bind=engine)
    ensure_peer_request_columns()


def ensure_peer_request_columns() -> None:
    existing = {column["name"] for column in inspect(engine).get_columns("peer_requests")}
    columns = {
        "local_link_address": "VARCHAR(128) NOT NULL DEFAULT ''",
        "peer_link_address": "VARCHAR(128) NOT NULL DEFAULT ''",
        "deploy_status": "VARCHAR(32) NOT NULL DEFAULT 'not_deployed'",
        "deploy_output": "TEXT NOT NULL DEFAULT ''",
        "deployed_at": "DATETIME",
    }
    missing = [(name, ddl) for name, ddl in columns.items() if name not in existing]
    if not missing:
        return
    with engine.begin() as conn:
        for name, ddl in missing:
            conn.execute(text(f"ALTER TABLE peer_requests ADD COLUMN {name} {ddl}"))


def seed_defaults(db: Session, settings: Settings) -> None:
    node = db.query(Node).filter(Node.name == "local").one_or_none()
    if node is None:
        db.add(
            Node(
                name="local",
                location="default",
                agent_url=settings.default_agent_url,
                agent_token=settings.default_agent_token,
                enabled=True,
            )
        )
        db.commit()
