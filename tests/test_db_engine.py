from unittest.mock import patch

from sqlalchemy.engine import URL

from fief.db.engine import create_engine
from fief.settings import settings


def _postgres_url() -> URL:
    return URL.create("postgresql+asyncpg", username="u", password="p", host="pooler.invalid", port=25061, database="fief-pool")


def _connect_args_used():
    with patch("fief.db.engine.create_async_engine") as factory:
        create_engine((_postgres_url(), {}))
    return factory.call_args.kwargs["connect_args"]


def test_direct_connections_send_timeouts_as_startup_parameters():
    with patch.object(settings, "database_pooled", False):
        connect_args = _connect_args_used()
    assert connect_args["server_settings"] == {
        "statement_timeout": str(settings.database_statement_timeout),
        "idle_in_transaction_session_timeout": str(settings.database_idle_in_transaction_timeout),
    }
    assert connect_args["command_timeout"] == 60


def test_pooled_connections_send_no_startup_parameters():
    # PgBouncer in transaction mode rejects statement_timeout at startup;
    # the role defaults carry it instead. The client-side bound stays.
    with patch.object(settings, "database_pooled", True):
        connect_args = _connect_args_used()
    assert "server_settings" not in connect_args
    assert connect_args["command_timeout"] == 60
