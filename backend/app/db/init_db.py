from sqlalchemy.orm import Session

from app.config import Settings
from app.db.models import Node
from app.db.session import Base, engine


def create_schema() -> None:
    Base.metadata.create_all(bind=engine)


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
