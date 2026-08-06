"""Inline migration script for OSEye storage.

Provides run_migrations(engine) which creates all tables and installs
PostgreSQL immutability triggers for SEC-0002 compliance.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

from oseye.storage.models import Base


async def run_migrations(engine: AsyncEngine) -> None:
    """Create all tables and install immutability triggers.

    For PostgreSQL backends, installs BEFORE UPDATE OR DELETE triggers on
    decisions and custody_log tables (SEC-0002 — immutable legal journal).
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if engine.dialect.name == "postgresql":
            await _install_immutability_triggers(conn)


async def _install_immutability_triggers(conn: AsyncConnection) -> None:
    """SEC-0002: prevent UPDATE/DELETE on decisions and custody_log.

    These tables form the immutable legal journal. Any attempt to mutate
    existing rows raises a database-level exception that cannot be bypassed
    by application code.
    """
    from sqlalchemy import text  # local import to keep top-level clean

    statements = [
        # Shared trigger function
        """
        CREATE OR REPLACE FUNCTION prevent_mutation()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'immutable record: % on table % is not allowed',
                TG_OP, TG_TABLE_NAME;
            RETURN NULL;
        END;
        $$ LANGUAGE plpgsql;
        """,
        # decisions table — block UPDATE and DELETE
        """
        DROP TRIGGER IF EXISTS prevent_decision_mutation ON decisions;
        """,
        """
        CREATE TRIGGER prevent_decision_mutation
        BEFORE UPDATE OR DELETE ON decisions
        FOR EACH ROW EXECUTE FUNCTION prevent_mutation();
        """,
        # custody_log table — block UPDATE and DELETE
        """
        DROP TRIGGER IF EXISTS prevent_custody_mutation ON custody_log;
        """,
        """
        CREATE TRIGGER prevent_custody_mutation
        BEFORE UPDATE OR DELETE ON custody_log
        FOR EACH ROW EXECUTE FUNCTION prevent_mutation();
        """,
    ]

    for stmt in statements:
        await conn.execute(text(stmt))
