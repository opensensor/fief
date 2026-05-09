"""Unit tests for the MFA-2 UserWebAuthnCredential SQLAlchemy model.

These tests assert column metadata (types, defaults, nullability, indexes,
unique constraints) and the User.webauthn_credentials back-relationship —
they don't require a DB round-trip, so they run cheaply.
"""

from __future__ import annotations

from sqlalchemy import BigInteger, Boolean, LargeBinary, Text
from sqlalchemy.orm import RelationshipProperty

from fief.models import UserWebAuthnCredential
from fief.models.generics import GUID, TIMESTAMPAware
from fief.models.user import User


def test_user_webauthn_credential_imports_from_models_package():
    # Module-level `from fief.models import UserWebAuthnCredential` must work;
    # the import itself at the top of this file is the assertion.
    assert UserWebAuthnCredential is not None


def test_user_webauthn_credential_tablename_has_user_webauthn_credentials_suffix():
    # Table prefix (default "fief_") is applied at import time via
    # ``Base.__init_subclass__`` -> ``get_prefixed_tablename``.
    assert UserWebAuthnCredential.__tablename__.endswith("user_webauthn_credentials")


def test_user_webauthn_credential_user_id_is_fk_to_users_with_cascade_delete():
    column = UserWebAuthnCredential.__table__.c.user_id
    assert column.nullable is False
    assert column.index is True
    fks = list(column.foreign_keys)
    assert len(fks) == 1
    fk = fks[0]
    assert fk.column.table.name.endswith("users")
    assert fk.ondelete == "CASCADE"


def test_user_webauthn_credential_credential_id_is_unique_indexed_bytes():
    column = UserWebAuthnCredential.__table__.c.credential_id
    assert isinstance(column.type, LargeBinary)
    assert column.nullable is False
    assert column.unique is True
    assert column.index is True


def test_user_webauthn_credential_public_key_is_bytes_not_null():
    column = UserWebAuthnCredential.__table__.c.public_key
    assert isinstance(column.type, LargeBinary)
    assert column.nullable is False


def test_user_webauthn_credential_sign_count_default_zero():
    column = UserWebAuthnCredential.__table__.c.sign_count
    assert isinstance(column.type, BigInteger)
    assert column.nullable is False
    assert column.default.arg == 0
    # server default is "0"
    assert column.server_default is not None


def test_user_webauthn_credential_transports_is_nullable_text():
    column = UserWebAuthnCredential.__table__.c.transports
    assert isinstance(column.type, Text)
    assert column.nullable is True


def test_user_webauthn_credential_aaguid_is_nullable_guid():
    column = UserWebAuthnCredential.__table__.c.aaguid
    assert isinstance(column.type, GUID)
    assert column.nullable is True


def test_user_webauthn_credential_backup_eligible_is_bool_default_false():
    column = UserWebAuthnCredential.__table__.c.backup_eligible
    assert isinstance(column.type, Boolean)
    assert column.nullable is False
    assert column.default.arg is False


def test_user_webauthn_credential_backup_state_is_bool_default_false():
    column = UserWebAuthnCredential.__table__.c.backup_state
    assert isinstance(column.type, Boolean)
    assert column.nullable is False
    assert column.default.arg is False


def test_user_webauthn_credential_label_is_nullable_text():
    column = UserWebAuthnCredential.__table__.c.label
    assert isinstance(column.type, Text)
    assert column.nullable is True


def test_user_webauthn_credential_attestation_obj_is_nullable_bytes():
    column = UserWebAuthnCredential.__table__.c.attestation_obj
    assert isinstance(column.type, LargeBinary)
    assert column.nullable is True


def test_user_webauthn_credential_last_used_at_is_nullable_timestamp():
    column = UserWebAuthnCredential.__table__.c.last_used_at
    assert isinstance(column.type, TIMESTAMPAware)
    assert column.nullable is True


def test_user_webauthn_credential_has_created_and_updated_at_columns():
    columns = UserWebAuthnCredential.__table__.c
    assert "created_at" in columns
    assert "updated_at" in columns


def test_user_webauthn_credential_has_uuid_primary_key():
    pk_columns = list(UserWebAuthnCredential.__table__.primary_key.columns)
    assert len(pk_columns) == 1
    assert pk_columns[0].name == "id"


def test_transports_list_returns_empty_for_none():
    cred = UserWebAuthnCredential()
    cred.transports = None
    assert cred.transports_list == []


def test_transports_list_returns_empty_for_empty_string():
    cred = UserWebAuthnCredential()
    cred.transports = ""
    assert cred.transports_list == []


def test_transports_list_parses_comma_separated_values():
    cred = UserWebAuthnCredential()
    cred.transports = "internal,hybrid"
    assert cred.transports_list == ["internal", "hybrid"]


def test_transports_list_strips_whitespace_and_drops_empties():
    cred = UserWebAuthnCredential()
    cred.transports = "internal, hybrid , ,usb"
    assert cred.transports_list == ["internal", "hybrid", "usb"]


def test_user_webauthn_credentials_relationship_declared_on_user():
    rel = User.webauthn_credentials.property
    assert isinstance(rel, RelationshipProperty)
    assert rel.uselist is True
    assert rel.mapper.class_ is UserWebAuthnCredential
    assert rel.back_populates == "user"
    assert "delete-orphan" in rel.cascade
    assert "delete" in rel.cascade


def test_user_webauthn_credential_user_relationship_back_populates():
    rel = UserWebAuthnCredential.user.property
    assert isinstance(rel, RelationshipProperty)
    assert rel.mapper.class_ is User
    assert rel.back_populates == "webauthn_credentials"
