#!/usr/bin/env python3
"""Migrate a v1 dn42-autopeer SQLite DB to the v2 schema (Agent→Node, integer IDs → UUIDs).

Standalone — needs only the Python standard library, not the app or its deps. It rebuilds the three
affected tables in place, remapping every integer primary key to a UUID and the ``agent_id`` foreign
keys to the new ``node_id`` UUIDs:

    agents          -> nodes          (id INTEGER -> VARCHAR(36) UUID; + asn/dn42_ipv4/dn42_ipv6)
    peer_requests   -> peer_requests  (id INTEGER -> UUID; agent_id INTEGER -> node_id UUID)
    lg_queries      -> lg_queries     (agent_id INTEGER -> node_id UUID; id stays INTEGER)

The users / asn_identities / telegram_bindings / auth_challenges tables are untouched (they keep
integer IDs). A timestamped backup of the database file is written before any change.

Usage:
    python3 backend/scripts/migrate_to_uuid_nodes.py [--db PATH] [--no-backup]

Run it once, while the backend is stopped. Fresh installs do NOT need this — the app creates the
v2 schema on first startup; this is only for databases created by the previous (integer-ID) version.
"""

from __future__ import annotations

import argparse
import shutil
import sqlite3
import sys
import time
import uuid
from pathlib import Path

DEFAULT_DB = Path(__file__).resolve().parent.parent / "autopeer.db"

# v2 table DDL. Column NAMES must match app/db/models.py; SQLite is dynamically typed, so the app's
# SQLAlchemy ORM (which addresses columns by name) works against these regardless of declared type.
# The unique index preserves the one-peer-per-node-per-ASN invariant (also enforced app-side).
NODES_DDL = """
CREATE TABLE nodes (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    name VARCHAR(64) NOT NULL,
    location VARCHAR(128) NOT NULL DEFAULT '',
    url VARCHAR(512) NOT NULL,
    token VARCHAR(255) NOT NULL DEFAULT '',
    wg_public_key VARCHAR(128) NOT NULL DEFAULT '',
    asn VARCHAR(32) NOT NULL DEFAULT '',
    dn42_ipv4 VARCHAR(64) NOT NULL DEFAULT '',
    dn42_ipv6 VARCHAR(64) NOT NULL DEFAULT '',
    enabled BOOLEAN NOT NULL DEFAULT 1,
    last_seen_at DATETIME,
    system_status_json TEXT NOT NULL DEFAULT '{}',
    created_at DATETIME NOT NULL
)
"""

PEERS_DDL = """
CREATE TABLE peer_requests_v2 (
    id VARCHAR(36) NOT NULL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    asn VARCHAR(32) NOT NULL,
    node_id VARCHAR(36) NOT NULL,
    tunnel_type VARCHAR(32) NOT NULL DEFAULT 'wireguard',
    endpoint VARCHAR(255) NOT NULL DEFAULT '',
    wg_public_key VARCHAR(128) NOT NULL,
    wg_mtu INTEGER NOT NULL DEFAULT 1420,
    local_link_address VARCHAR(128) NOT NULL DEFAULT '',
    peer_link_address VARCHAR(128) NOT NULL DEFAULT '',
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    admin_note TEXT NOT NULL DEFAULT '',
    deploy_status VARCHAR(32) NOT NULL DEFAULT 'not_deployed',
    deploy_output TEXT NOT NULL DEFAULT '',
    deployed_at DATETIME,
    created_at DATETIME NOT NULL,
    updated_at DATETIME NOT NULL
)
"""

LG_DDL = """
CREATE TABLE lg_queries_v2 (
    id INTEGER NOT NULL PRIMARY KEY,
    user_id INTEGER,
    node_id VARCHAR(36) NOT NULL,
    query_type VARCHAR(32) NOT NULL,
    target VARCHAR(255) NOT NULL,
    ok BOOLEAN NOT NULL DEFAULT 0,
    result TEXT NOT NULL DEFAULT '',
    created_at DATETIME NOT NULL
)
"""

NODE_DEFAULTS = {
    "location": "",
    "url": "",
    "token": "",
    "wg_public_key": "",
    "enabled": 1,
    "last_seen_at": None,
    "system_status_json": "{}",
    "created_at": None,
}
PEER_DEFAULTS = {
    "tunnel_type": "wireguard",
    "endpoint": "",
    "wg_mtu": 1420,
    "local_link_address": "",
    "peer_link_address": "",
    "status": "pending",
    "admin_note": "",
    "deploy_status": "not_deployed",
    "deploy_output": "",
    "deployed_at": None,
    "created_at": None,
    "updated_at": None,
}


def table_names(con: sqlite3.Connection) -> set[str]:
    return {r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def column_names(con: sqlite3.Connection, table: str) -> set[str]:
    return {r[1] for r in con.execute(f"PRAGMA table_info({table})")}


def insert_row(con: sqlite3.Connection, table: str, values: dict) -> None:
    cols = ", ".join(values)
    placeholders = ", ".join("?" for _ in values)
    con.execute(f"INSERT INTO {table} ({cols}) VALUES ({placeholders})", list(values.values()))


def _pick(row: dict, key: str, default):
    value = row.get(key, default)
    return default if value is None and default is not None else value


def migrate(db_path: Path, *, backup: bool) -> int:
    if not db_path.exists():
        print(f"error: database not found: {db_path}", file=sys.stderr)
        return 2

    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    try:
        tables = table_names(con)
        if "agents" not in tables:
            print("No legacy 'agents' table found — nothing to migrate (already v2 or fresh DB).")
            return 0
        if "nodes" in tables and (con.execute("SELECT COUNT(*) FROM nodes").fetchone()[0] or 0) > 0:
            print(
                "error: both 'agents' and a non-empty 'nodes' table exist; refusing to migrate. "
                "Restore a clean v1 backup and re-run.",
                file=sys.stderr,
            )
            return 3
    finally:
        con.close()

    if backup:
        backup_path = db_path.with_name(f"{db_path.name}.bak-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(db_path, backup_path)
        print(f"Backed up {db_path} -> {backup_path}")

    con = sqlite3.connect(str(db_path))
    con.row_factory = sqlite3.Row
    try:
        con.execute("PRAGMA foreign_keys=OFF")
        agent_cols = column_names(con, "agents")
        node_id_map = {row["id"]: str(uuid.uuid4()) for row in con.execute("SELECT id FROM agents")}
        peer_id_map = {
            row["id"]: str(uuid.uuid4()) for row in con.execute("SELECT id FROM peer_requests")
        }

        # --- nodes (from agents) ---
        if "nodes" in table_names(con):
            con.execute("DROP TABLE nodes")  # drop an empty app-created v2 table, if any
        con.execute(NODES_DDL)
        for row in con.execute("SELECT * FROM agents"):
            row = dict(row)
            values = {"id": node_id_map[row["id"]], "name": row["name"]}
            for col, default in NODE_DEFAULTS.items():
                if col in agent_cols:
                    values[col] = _pick(row, col, default)
                else:
                    values[col] = default
            values["asn"] = ""
            values["dn42_ipv4"] = ""
            values["dn42_ipv6"] = ""
            insert_row(con, "nodes", values)

        # --- peer_requests (rebuild with UUID id + node_id) ---
        peer_cols = column_names(con, "peer_requests")
        if "agent_id" not in peer_cols:
            raise RuntimeError(
                "peer_requests has no 'agent_id' column — unexpected schema, aborting."
            )
        con.execute(PEERS_DDL)
        for row in con.execute("SELECT * FROM peer_requests"):
            row = dict(row)
            values = {
                "id": peer_id_map[row["id"]],
                "user_id": row["user_id"],
                "asn": row["asn"],
                "node_id": node_id_map[row["agent_id"]],
                "wg_public_key": _pick(row, "wg_public_key", ""),
            }
            for col, default in PEER_DEFAULTS.items():
                values[col] = _pick(row, col, default) if col in peer_cols else default
            insert_row(con, "peer_requests_v2", values)
        con.execute("DROP TABLE peer_requests")
        con.execute("ALTER TABLE peer_requests_v2 RENAME TO peer_requests")
        con.execute("CREATE UNIQUE INDEX uq_peer_node_asn ON peer_requests (node_id, asn)")
        con.execute("CREATE INDEX ix_peer_requests_node_id ON peer_requests (node_id)")
        con.execute("CREATE INDEX ix_peer_requests_user_id ON peer_requests (user_id)")

        # --- lg_queries (retype agent_id -> node_id; id stays INTEGER) ---
        lg_migrated = 0
        if "lg_queries" in table_names(con) and "agent_id" in column_names(con, "lg_queries"):
            con.execute(LG_DDL)
            for row in con.execute("SELECT * FROM lg_queries"):
                row = dict(row)
                node_id = node_id_map.get(row.get("agent_id"))
                if node_id is None:
                    continue  # orphan query referencing a missing agent; drop it
                insert_row(
                    con,
                    "lg_queries_v2",
                    {
                        "id": row["id"],
                        "user_id": row.get("user_id"),
                        "node_id": node_id,
                        "query_type": row.get("query_type", ""),
                        "target": row.get("target", ""),
                        "ok": _pick(row, "ok", 0),
                        "result": _pick(row, "result", ""),
                        "created_at": row.get("created_at"),
                    },
                )
                lg_migrated += 1
            con.execute("DROP TABLE lg_queries")
            con.execute("ALTER TABLE lg_queries_v2 RENAME TO lg_queries")
            con.execute("CREATE INDEX ix_lg_queries_node_id ON lg_queries (node_id)")

        con.execute("DROP TABLE agents")
        con.commit()
    except Exception:
        con.rollback()
        print(
            "Migration failed; database rolled back. Restore from the backup if needed.",
            file=sys.stderr,
        )
        raise
    finally:
        con.close()

    print(
        f"Migrated {len(node_id_map)} node(s), {len(peer_id_map)} peer(s), "
        f"{lg_migrated} looking-glass log row(s) to UUID IDs."
    )
    print("Done. Start the backend; it will create any remaining v2 columns automatically.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--db", type=Path, default=DEFAULT_DB, help="path to the SQLite DB file")
    parser.add_argument("--no-backup", action="store_true", help="skip the pre-migration backup")
    args = parser.parse_args()
    return migrate(args.db, backup=not args.no_backup)


if __name__ == "__main__":
    raise SystemExit(main())
