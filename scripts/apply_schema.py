#!/usr/bin/env python3
"""Apply ClickHouse schema using admin credentials."""

import os
import sys
from pathlib import Path

import clickhouse_connect

def main():
    host = os.environ.get("CLICKHOUSE_HOST", "localhost")
    port = int(os.environ.get("CLICKHOUSE_PORT", "8123"))
    admin_user = os.environ.get("CLICKHOUSE_ADMIN_USER", "default")
    admin_pass = os.environ.get("CLICKHOUSE_ADMIN_PASSWORD", "")
    secure_env = os.environ.get("CLICKHOUSE_SECURE", "").lower()
    secure = secure_env in ("1", "true", "yes") if secure_env else port == 8443

    schema_path = Path(__file__).parent / "schema.sql"

    print(f"Connecting to ClickHouse at {host}:{port} as {admin_user}...")

    client = clickhouse_connect.get_client(
        host=host,
        port=port,
        username=admin_user,
        password=admin_pass,
        secure=secure,
    )

    sql = schema_path.read_text()
    app_pass = os.environ.get("CLICKHOUSE_APP_PASSWORD")
    if app_pass:
        sql = sql.replace("'hackathon2026'", "'" + app_pass.replace("\\", "\\\\").replace("'", "\\'") + "'")

    # Split by semicolon and execute each statement
    statements = [s.strip() for s in sql.split(";") if s.strip()]

    for stmt in statements:
        if stmt:
            print(f"Executing: {stmt[:60]}...")
            client.command(stmt)

    if app_pass:
        client.command(
            "ALTER USER cyberdefense_app IDENTIFIED BY '"
            + app_pass.replace("\\", "\\\\").replace("'", "\\'") + "'"
        )

    print("Schema applied successfully!")

    # Verify tables
    result = client.query("SHOW TABLES FROM cyberdefense")
    print(f"Tables created: {[row[0] for row in result.result_rows]}")

if __name__ == "__main__":
    main()
