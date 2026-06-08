from sqlalchemy import inspect, text

from app.db.session import Base, engine
from app.peer.validation import DEFAULT_WIREGUARD_MTU


def create_schema() -> None:
    Base.metadata.create_all(bind=engine)
    _ensure_node_columns()
    _ensure_peer_request_columns()
    _ensure_indexes()


def _ensure_node_columns() -> None:
    """Backfill columns added to ``Node`` after a database was first created.

    ``Base.metadata.create_all`` only creates missing tables, never missing columns, so a
    column introduced later must be added with an idempotent ALTER on an existing DB.
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
    additions = {
        "wg_mtu": f"INTEGER NOT NULL DEFAULT {DEFAULT_WIREGUARD_MTU}",
        "peer_dn42_ipv4": "VARCHAR(64) NOT NULL DEFAULT ''",
        "peer_dn42_ipv6": "VARCHAR(64) NOT NULL DEFAULT ''",
        "bgp_extended": "BOOLEAN NOT NULL DEFAULT 1",
    }
    for name, ddl in additions.items():
        if name not in columns:
            with engine.begin() as conn:
                conn.execute(text(f"ALTER TABLE peer_requests ADD COLUMN {name} {ddl}"))


def _ensure_indexes() -> None:
    """Create sort indexes used by admin list views, idempotently."""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    indexes = {
        "peer_requests": {
            "ix_peer_requests_created_at": "created_at",
            "ix_peer_requests_updated_at": "updated_at",
        },
        "lg_queries": {
            "ix_lg_queries_created_at": "created_at",
        },
    }
    with engine.begin() as conn:
        for table, table_indexes in indexes.items():
            if table not in tables:
                continue
            columns = {col["name"] for col in inspector.get_columns(table)}
            existing = {idx["name"] for idx in inspector.get_indexes(table)}
            for name, column in table_indexes.items():
                if column in columns and name not in existing:
                    conn.execute(text(f"CREATE INDEX {name} ON {table} ({column})"))
