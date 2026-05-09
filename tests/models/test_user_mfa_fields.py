"""Unit tests for the MFA-related columns/relationships added in T8.

These tests assert column metadata (defaults, nullability) and relationship
declarations directly off the SQLAlchemy mapped classes — they don't require
a DB round-trip, so they run cheaply and don't depend on the heavy test
fixtures used by the integration tests.
"""

from __future__ import annotations

from sqlalchemy.orm import RelationshipProperty

from fief.models.login_session import LoginSession
from fief.models.user import User
from fief.models.user_mfa_recovery_code import UserMfaRecoveryCode
from fief.models.user_totp_secret import UserTotpSecret


def test_user_mfa_enabled_column_defaults_to_false():
    column = User.__table__.c.mfa_enabled
    assert column.default.arg is False
    assert column.nullable is False


def test_user_mfa_recovery_codes_relationship_declared():
    """The collection back-relationship to UserMfaRecoveryCode must be
    declared on User so /login can read user.mfa_recovery_codes without an
    extra query against the recovery codes table.
    """
    rel = User.mfa_recovery_codes.property
    assert isinstance(rel, RelationshipProperty)
    assert rel.uselist is True
    assert rel.mapper.class_ is UserMfaRecoveryCode
    assert rel.back_populates == "user"
    assert "delete-orphan" in rel.cascade


def test_user_totp_secret_relationship_declared():
    rel = User.totp_secret.property
    assert isinstance(rel, RelationshipProperty)
    assert rel.uselist is False
    assert rel.mapper.class_ is UserTotpSecret
    assert rel.back_populates == "user"
    assert "delete-orphan" in rel.cascade


def test_user_can_assign_empty_recovery_codes_list():
    """A fresh User instance accepts an empty mfa_recovery_codes assignment
    (collection attribute is mapped and writable).
    """
    user = User()
    user.mfa_recovery_codes = []
    assert list(user.mfa_recovery_codes) == []


def test_login_session_mfa_pending_user_id_is_nullable_fk_to_users():
    column = LoginSession.__table__.c.mfa_pending_user_id
    assert column.nullable is True
    assert column.default is None or column.default.arg is None
    # Single FK to the users table; resolve its referenced table name.
    fks = list(column.foreign_keys)
    assert len(fks) == 1
    referenced_table = fks[0].column.table.name
    assert referenced_table.endswith("users")


def test_login_session_mfa_attempts_count_defaults_to_zero():
    column = LoginSession.__table__.c.mfa_attempts_count
    assert column.default.arg == 0
    assert column.nullable is False


def test_login_session_mfa_locked_until_is_nullable_timestamp():
    column = LoginSession.__table__.c.mfa_locked_until
    assert column.nullable is True
