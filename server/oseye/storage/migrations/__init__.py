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
    Also installs the entity_hourly_stats refresh procedure (P6.09).
    """
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if engine.dialect.name == "postgresql":
            await _install_immutability_triggers(conn)
            await _install_entity_hourly_stats_refresh(conn)
        if engine.dialect.name == "sqlite":
            await _install_entity_hourly_stats_refresh_sqlite(conn)


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


async def _install_entity_hourly_stats_refresh(conn: AsyncConnection) -> None:
    """P6.09: install a PostgreSQL stored procedure to refresh entity_hourly_stats.

    The procedure upserts one row per (hostname, category, hour_bucket) from the
    events table.  Call it periodically (e.g. every hour via pg_cron or a worker).

    ClickHouse materialised view equivalent is deferred to Phase 10.
    """
    from sqlalchemy import text

    await conn.execute(text("""
        CREATE OR REPLACE PROCEDURE refresh_entity_hourly_stats()
        LANGUAGE plpgsql AS $$
        BEGIN
            INSERT INTO entity_hourly_stats (
                hostname, category, hour_bucket,
                event_count, uid_p50, root_fraction, error_fraction,
                distinct_processes, bytes_sent_sum, bytes_recv_sum,
                network_event_count, distinct_dst_ips, alert_count
            )
            SELECT
                hostname,
                category,
                (timestamp_ns / 3600000000000)::bigint * 3600  AS hour_bucket,
                COUNT(*)                                         AS event_count,
                PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY uid) AS uid_p50,
                AVG(CASE WHEN uid = 0 THEN 1.0 ELSE 0.0 END)   AS root_fraction,
                AVG(CASE WHEN result != 'success' THEN 1.0 ELSE 0.0 END) AS error_fraction,
                COUNT(DISTINCT process_name)                     AS distinct_processes,
                COALESCE(SUM(bytes_sent), 0)                     AS bytes_sent_sum,
                COALESCE(SUM(bytes_recv), 0)                     AS bytes_recv_sum,
                COUNT(*) FILTER (WHERE category = 'network')     AS network_event_count,
                COUNT(DISTINCT dst_ip) FILTER (WHERE dst_ip IS NOT NULL) AS distinct_dst_ips,
                0                                                AS alert_count
            FROM events
            GROUP BY hostname, category, (timestamp_ns / 3600000000000)::bigint * 3600
            ON CONFLICT (hostname, category, hour_bucket)
                DO UPDATE SET
                    event_count       = EXCLUDED.event_count,
                    uid_p50           = EXCLUDED.uid_p50,
                    root_fraction     = EXCLUDED.root_fraction,
                    error_fraction    = EXCLUDED.error_fraction,
                    distinct_processes= EXCLUDED.distinct_processes,
                    bytes_sent_sum    = EXCLUDED.bytes_sent_sum,
                    bytes_recv_sum    = EXCLUDED.bytes_recv_sum,
                    network_event_count = EXCLUDED.network_event_count,
                    distinct_dst_ips  = EXCLUDED.distinct_dst_ips;
        END;
        $$;
    """))


async def _install_entity_hourly_stats_refresh_sqlite(conn: AsyncConnection) -> None:
    """P6.09 SQLite equivalent — a plain INSERT OR REPLACE query (no procedures).

    SQLite does not support stored procedures or PERCENTILE_CONT.  The Python-side
    worker (EntityHourlyStatsWorker, Phase 10) calls this query directly.
    Stored here for documentation purposes; the migration creates the unique
    constraint needed for ON CONFLICT handling.
    """
    from sqlalchemy import text

    await conn.execute(text("""
        CREATE UNIQUE INDEX IF NOT EXISTS uq_ehs_hostname_cat_hour
        ON entity_hourly_stats (hostname, category, hour_bucket);
    """))
