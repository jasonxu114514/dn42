from app.db.session import Base, engine


def create_schema() -> None:
    Base.metadata.create_all(bind=engine)
