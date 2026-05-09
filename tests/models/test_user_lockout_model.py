"""Unit tests for the SEC-1 UserLockout SQLAlchemy model.

These tests assert column metadata (defaults, nullability, primary key)
and the User.lockout back-relationship — they don't require a DB
round-trip, so they run cheaply.
"""

from __future__ import annotations

from sqlalchemy.orm import RelationshipProperty

from fief.models import UserLockout
from fief.models.user import User


def test_user_lockout_imports_from_models_package():
    # Module-level `from fief.models import UserLockout` must work; the
    # import itself at the top of this file is the assertion.
    assert UserLockout is not None


def test_user_lockout_tablename_has_user_lockouts_suffix():
    # Table prefix (default "fief_") is applied at import time via
    # ``Base.__init_subclass__`` -> ``get_prefixed_tablename``.
    assert UserLockout.__tablename__.endswith("user_lockouts")


def test_user_lockout_failed_count_defaults_to_zero():
    column = UserLockout.__table__.c.failed_count
    assert column.default.arg == 0
    assert column.nullable is False


def test_user_lockout_locked_until_is_nullable():
    column = UserLockout.__table__.c.locked_until
    assert column.nullable is True


def test_user_lockout_primary_key_is_user_id():
    pk_columns = list(UserLockout.__table__.primary_key.columns)
    assert len(pk_columns) == 1
    assert pk_columns[0].name == "user_id"


def test_user_lockout_user_id_is_fk_to_users_with_cascade_delete():
    column = UserLockout.__table__.c.user_id
    fks = list(column.foreign_keys)
    assert len(fks) == 1
    fk = fks[0]
    assert fk.column.table.name.endswith("users")
    assert fk.ondelete == "CASCADE"


def test_user_lockout_has_created_and_updated_at_columns():
    columns = UserLockout.__table__.c
    assert "created_at" in columns
    assert "updated_at" in columns


def test_user_lockout_relationship_declared_on_user():
    rel = User.lockout.property
    assert isinstance(rel, RelationshipProperty)
    assert rel.uselist is False
    assert rel.mapper.class_ is UserLockout
    assert rel.back_populates == "user"
    assert "delete-orphan" in rel.cascade


def test_user_lockout_user_relationship_back_populates_lockout():
    rel = UserLockout.user.property
    assert isinstance(rel, RelationshipProperty)
    assert rel.mapper.class_ is User
    assert rel.back_populates == "lockout"
