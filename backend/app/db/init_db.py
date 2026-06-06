import secrets

from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import Agent
from app.db.session import Base, engine


def create_schema() -> None:
    Base.metadata.create_all(bind=engine)


def seed_defaults(db: Session, settings: Settings) -> None:
    agent = db.query(Agent).filter(Agent.name == "local").one_or_none()
    if agent is None:
        agent = Agent(
            name="local",
            location="default",
            url=settings.default_agent_url,
            token=secrets.token_urlsafe(32),
            enabled=True,
        )
        db.add(agent)
    db.commit()
