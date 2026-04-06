from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine

from fief.db.types import DatabaseConnectionParameters
from fief.settings import settings


def create_engine(
    database_connection_parameters: DatabaseConnectionParameters,
) -> AsyncEngine:
    database_url, connect_args = database_connection_parameters
    dialect_name = database_url.get_dialect().name
    engine_params = {
        "connect_args": connect_args,
        "echo": False,
        "use_insertmanyvalues": False,  # The default doesn't work with asyncpg starting 2.0.10. Should monitor that.
        "pool_recycle": settings.database_pool_recycle_seconds,
        "pool_pre_ping": settings.database_pool_pre_ping,
    }
    if dialect_name != "sqlite":
        engine_params.update(
            {
                "pool_size": settings.database_pool_size,
                "max_overflow": settings.database_pool_max_overflow,
                "pool_timeout": settings.database_pool_timeout,
                "pool_reset_on_return": "rollback",
            }
        )
    # Set statement timeout for PostgreSQL via asyncpg server_settings
    if dialect_name == "postgresql":
        connect_args.setdefault("server_settings", {})
        connect_args["server_settings"]["statement_timeout"] = str(
            settings.database_statement_timeout
        )
        connect_args["server_settings"]["idle_in_transaction_session_timeout"] = str(
            settings.database_idle_in_transaction_timeout
        )
        # Client-side command timeout (asyncpg, in seconds). PostgreSQL's
        # statement_timeout exempts ROLLBACK/ABORT, so a hung ROLLBACK on a
        # broken TCP connection will wait forever without this.
        connect_args["command_timeout"] = 60
    engine = create_async_engine(database_url, **engine_params)

    # Special tweak for SQLite to better handle transaction
    # See: https://docs.sqlalchemy.org/en/14/dialects/sqlite.html#serializable-isolation-savepoints-transactional-ddl
    if dialect_name == "sqlite":

        @event.listens_for(engine.sync_engine, "connect")
        def do_connect(dbapi_connection, connection_record):
            # disable pysqlite's emitting of the BEGIN statement entirely.
            # also stops it from emitting COMMIT before any DDL.
            dbapi_connection.isolation_level = None

            # Enable SQLite foreign key support, which is not enabled by default
            # See: https://www.sqlite.org/foreignkeys.html#fk_enable
            dbapi_connection.execute("pragma foreign_keys=ON")

        @event.listens_for(engine.sync_engine, "begin")
        def do_begin(conn):
            # emit our own BEGIN
            conn.exec_driver_sql("BEGIN")

    return engine


def create_async_session_maker(engine: AsyncEngine):
    return async_sessionmaker(engine, expire_on_commit=False)


__all__ = [
    "create_engine",
    "create_async_session_maker",
]
