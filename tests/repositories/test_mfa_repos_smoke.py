"""Smoke tests for the MFA repositories.

These assertions don't talk to the database — they only verify the
repository classes are importable, expose the expected methods with the
right signatures, and inherit from the project's BaseRepository pattern.
Real CRUD coverage lives with the service-level tests in T23.
"""

from __future__ import annotations

import inspect


def test_user_totp_secret_repository_importable_from_package():
    from fief.repositories import UserTotpSecretRepository

    assert UserTotpSecretRepository is not None


def test_user_mfa_recovery_code_repository_importable_from_package():
    from fief.repositories import UserMfaRecoveryCodeRepository

    assert UserMfaRecoveryCodeRepository is not None


def test_user_totp_secret_repository_subclasses_base_repository():
    from fief.repositories import UserTotpSecretRepository
    from fief.repositories.base import BaseRepository

    assert issubclass(UserTotpSecretRepository, BaseRepository)


def test_user_mfa_recovery_code_repository_subclasses_base_repository():
    from fief.repositories import UserMfaRecoveryCodeRepository
    from fief.repositories.base import BaseRepository

    assert issubclass(UserMfaRecoveryCodeRepository, BaseRepository)


def test_user_totp_secret_repository_binds_correct_model():
    from fief.models import UserTotpSecret
    from fief.repositories import UserTotpSecretRepository

    assert UserTotpSecretRepository.model is UserTotpSecret


def test_user_mfa_recovery_code_repository_binds_correct_model():
    from fief.models import UserMfaRecoveryCode
    from fief.repositories import UserMfaRecoveryCodeRepository

    assert UserMfaRecoveryCodeRepository.model is UserMfaRecoveryCode


def test_user_totp_secret_repository_method_signatures():
    from fief.repositories import UserTotpSecretRepository

    expected = {
        "get_by_user_id": ["self", "user_id"],
        "get_confirmed_by_user_id": ["self", "user_id"],
        "delete_by_user_id": ["self", "user_id"],
    }

    for method_name, expected_params in expected.items():
        method = getattr(UserTotpSecretRepository, method_name, None)
        assert method is not None, f"{method_name} missing from repository"
        assert inspect.iscoroutinefunction(
            method
        ), f"{method_name} must be async"
        sig = inspect.signature(method)
        params = list(sig.parameters.keys())
        assert params == expected_params, (
            f"{method_name} signature mismatch: expected {expected_params}, got {params}"
        )


def test_user_mfa_recovery_code_repository_method_signatures():
    from fief.repositories import UserMfaRecoveryCodeRepository

    list_method = getattr(UserMfaRecoveryCodeRepository, "list_by_user_id", None)
    assert list_method is not None, "list_by_user_id missing from repository"
    assert inspect.iscoroutinefunction(list_method)
    list_sig = inspect.signature(list_method)
    list_params = list_sig.parameters
    assert list(list_params.keys()) == ["self", "user_id", "only_unused"]
    only_unused = list_params["only_unused"]
    assert only_unused.kind is inspect.Parameter.KEYWORD_ONLY
    assert only_unused.default is False

    delete_method = getattr(UserMfaRecoveryCodeRepository, "delete_by_user_id", None)
    assert delete_method is not None, "delete_by_user_id missing from repository"
    assert inspect.iscoroutinefunction(delete_method)
    assert list(inspect.signature(delete_method).parameters.keys()) == [
        "self",
        "user_id",
    ]

    mark_used = getattr(UserMfaRecoveryCodeRepository, "mark_used", None)
    assert mark_used is not None, "mark_used missing from repository"
    assert inspect.iscoroutinefunction(mark_used)
    assert list(inspect.signature(mark_used).parameters.keys()) == ["self", "code"]
