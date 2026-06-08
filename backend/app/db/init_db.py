from sqlalchemy import inspect, text

from app.db.session import Base, engine
from app.peer.validation import DEFAULT_WIREGUARD_MTU


def create_schema() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_node_columns()
    _ensure_peer_request_columns()


def _ensure_node_columns() -> None:
    """Backfill columns added to ``Node`` after a database was first created.

    ``Base.metadata.create_all`` only creates missing *tables*, never missing *columns*, so a
    column introduced later (here the per-node ``asn``/``dn42_ipv4``/``dn42_ipv6``) must be added
    with an idempotent ALTER on an existing DB. SQLite requires a DEFAULT when adding a NOT NULL
    column, which we supply. This runs on the ``nodes`` table (the int→UUID rename from the old
    ``agents`` table is handled once by scripts/migrate_to_uuid_nodes.py, not here).
    ``create_all`` 只建立缺少的*資料表*,不會補上缺少的*欄位*;此處對 ``nodes`` 以等冪 ALTER 補上
    日後新增的欄位。int→UUID 與 agents→nodes 的改名由 migrate_to_uuid_nodes.py 一次處理。
    """
    inspector = inspect(engine)
    if "nodes" not in inspector.get_table_names():
        return
    columns = {col["name"] for col in inspector.get_columns("nodes")}
    additions = {
        "wg_public_key": "VARCHAR(128) NOT NULL DEFAULT ''",
        "last_seen_at": "DATETIME",
        "system_status_json": "TEXT NOT NULL DEFAULT '{}'",
        "asn": "VARCHAR(32) NOT NULL DEFAULT ''",
        "dn42_ipv4": "VARCHAR(64) NOT NULL DEFAULT ''",
        "dn42_ipv6": "VARCHAR(64) NOT NULL DEFAULT ''",
    }
    for name, ddl in additions.items():
        if name not in columns:
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE nodes ADD COLUMN {name} {ddl}"))


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
