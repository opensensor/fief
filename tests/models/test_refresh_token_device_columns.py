"""Unit tests for UX-1 T5: RefreshToken device-annotation columns.

These assertions check column metadata only; no DB round-trip is required.
"""

from __future__ import annotations

from fief.models import RefreshToken


def test_refresh_token_has_created_ip_nullable():
    column = RefreshToken.__table__.c.created_ip
    assert column.nullable is True


def test_refresh_token_has_created_user_agent_nullable():
    column = RefreshToken.__table__.c.created_user_agent
    assert column.nullable is True


def test_refresh_token_has_last_seen_at_nullable():
    column = RefreshToken.__table__.c.last_seen_at
    assert column.nullable is True


def test_refresh_token_has_last_seen_ip_nullable():
    column = RefreshToken.__table__.c.last_seen_ip
    assert column.nullable is True


def test_refresh_token_user_id_is_indexed():
    # T5 keeps the model + DDL in sync with T3's CREATE INDEX.
    assert RefreshToken.__table__.c.user_id.index is True
