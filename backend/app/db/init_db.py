from sqlalchemy import inspect, text

from app.db.session import Base, engine
from app.peer.validation import DEFAULT_WIREGUARD_MTU


def create_schema() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_agent_columns()
    _ensure_peer_request_columns()


def _ensure_agent_columns() -> None:
    """Backfill columns added to ``Agent`` after a database was first created.

    ``Base.metadata.create_all`` only creates missing *tables*, never missing *columns*, so a column
    introduced later (here ``agents.wg_public_key``) must be added with an idempotent ALTER on an
    existing DB. SQLite requires a DEFAULT when adding a NOT NULL column, which we supply.
    ``create_all`` 只會建立缺少的*資料表*,不會補上缺少的*欄位*,因此日後新增的欄位(此處為
    ``agents.wg_public_key``)需在既有資料庫以等冪的 ALTER 補上。SQLite 新增 NOT NULL 欄位時必須
    提供 DEFAULT,故此處給定空字串。
    """
    inspector = inspect(engine)
    if "agents" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("agents")}
    if "wg_public_key" not in columns:
        with engine.begin() as conn:
            conn.execute(
                text("ALTER TABLE agents ADD COLUMN wg_public_key VARCHAR(128) NOT NULL DEFAULT ''")
            )


def _ensure_peer_request_columns() -> None:
    """Backfill columns added to ``PeerRequest`` after a database was first created."""
    inspector = inspect(engine)
    if "peer_requests" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("peer_requests")}
    if "wg_mtu" not in columns:
        with engine.begin() as conn:
            conn.execute(
                text(
                    "ALTER TABLE peer_requests "
                    f"ADD COLUMN wg_mtu INTEGER NOT NULL DEFAULT {DEFAULT_WIREGUARD_MTU}"
                )
            )
