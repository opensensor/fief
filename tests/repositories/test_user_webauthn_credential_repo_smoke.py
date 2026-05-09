"""Smoke tests for the UserWebAuthnCredentialRepository (MFA-2 T5).

These assertions don't talk to the database — they only verify the
repository class is importable, exposes the expected methods with the
right signatures, and inherits from the project's BaseRepository
pattern. Real CRUD coverage lives with the service-level tests in T6
and the route-level tests in T13/T14.
"""

from __future__ import annotations

import inspect
from datetime import datetime


def test_user_webauthn_credential_repository_importable_from_package():
    from fief.repositories import UserWebAuthnCredentialRepository

    assert UserWebAuthnCredentialRepository is not None


def test_user_webauthn_credential_repository_subclasses_base_repository():
    from fief.repositories import UserWebAuthnCredentialRepository
    from fief.repositories.base import BaseRepository

    assert issubclass(UserWebAuthnCredentialRepository, BaseRepository)


def test_user_webauthn_credential_repository_binds_correct_model():
    from fief.models import UserWebAuthnCredential
    from fief.repositories import UserWebAuthnCredentialRepository

    assert UserWebAuthnCredentialRepository.model is UserWebAuthnCredential


def test_list_by_user_id_signature():
    from fief.repositories import UserWebAuthnCredentialRepository

    method = getattr(UserWebAuthnCredentialRepository, "list_by_user_id", None)
    assert method is not None, "list_by_user_id missing from repository"
    assert inspect.iscoroutinefunction(method), "list_by_user_id must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "user_id"]


def test_get_by_credential_id_signature():
    from fief.repositories import UserWebAuthnCredentialRepository

    method = getattr(UserWebAuthnCredentialRepository, "get_by_credential_id", None)
    assert method is not None, "get_by_credential_id missing from repository"
    assert inspect.iscoroutinefunction(method), "get_by_credential_id must be async"
    sig = inspect.signature(method)
    params = sig.parameters
    assert list(params.keys()) == ["self", "credential_id"]
    assert params["credential_id"].annotation is bytes


def test_get_by_id_for_user_signature():
    from fief.repositories import UserWebAuthnCredentialRepository

    method = getattr(UserWebAuthnCredentialRepository, "get_by_id_for_user", None)
    assert method is not None, "get_by_id_for_user missing from repository"
    assert inspect.iscoroutinefunction(method), "get_by_id_for_user must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "id", "user_id"]


def test_delete_by_id_for_user_signature():
    from fief.repositories import UserWebAuthnCredentialRepository

    method = getattr(UserWebAuthnCredentialRepository, "delete_by_id_for_user", None)
    assert method is not None, "delete_by_id_for_user missing from repository"
    assert inspect.iscoroutinefunction(method), "delete_by_id_for_user must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "id", "user_id"]
    assert sig.return_annotation is int


def test_count_for_user_signature():
    from fief.repositories import UserWebAuthnCredentialRepository

    method = getattr(UserWebAuthnCredentialRepository, "count_for_user", None)
    assert method is not None, "count_for_user missing from repository"
    assert inspect.iscoroutinefunction(method), "count_for_user must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "user_id"]
    assert sig.return_annotation is int


def test_update_after_assertion_signature():
    from fief.repositories import UserWebAuthnCredentialRepository

    method = getattr(
        UserWebAuthnCredentialRepository, "update_after_assertion", None
    )
    assert method is not None, "update_after_assertion missing from repository"
    assert inspect.iscoroutinefunction(method), "update_after_assertion must be async"
    sig = inspect.signature(method)
    params = sig.parameters
    assert list(params.keys()) == ["self", "credential_id", "sign_count", "last_used_at"]
    # sign_count and last_used_at are keyword-only
    assert params["sign_count"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["last_used_at"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["credential_id"].annotation is bytes
    assert params["sign_count"].annotation is int
    assert params["last_used_at"].annotation is datetime


def test_rename_by_id_for_user_signature():
    from fief.repositories import UserWebAuthnCredentialRepository

    method = getattr(UserWebAuthnCredentialRepository, "rename_by_id_for_user", None)
    assert method is not None, "rename_by_id_for_user missing from repository"
    assert inspect.iscoroutinefunction(method), "rename_by_id_for_user must be async"
    sig = inspect.signature(method)
    params = sig.parameters
    assert list(params.keys()) == ["self", "id", "user_id", "label"]
    assert params["label"].annotation is str
    assert sig.return_annotation is int
