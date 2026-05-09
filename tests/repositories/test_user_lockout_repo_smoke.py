"""Smoke tests for the UserLockoutRepository (SEC-1 T8).

These assertions don't talk to the database — they only verify the
repository class is importable, exposes the expected methods with the
right signatures, and inherits from the project's BaseRepository
pattern. Real CRUD + ladder coverage lives with the service-level tests
in T20.
"""

from __future__ import annotations

import inspect


def test_user_lockout_repository_importable_from_package():
    from fief.repositories import UserLockoutRepository

    assert UserLockoutRepository is not None


def test_user_lockout_repository_subclasses_base_repository():
    from fief.repositories import UserLockoutRepository
    from fief.repositories.base import BaseRepository

    assert issubclass(UserLockoutRepository, BaseRepository)


def test_user_lockout_repository_binds_correct_model():
    from fief.models import UserLockout
    from fief.repositories import UserLockoutRepository

    assert UserLockoutRepository.model is UserLockout


def test_user_lockout_repository_get_by_user_id_signature():
    from fief.repositories import UserLockoutRepository

    method = getattr(UserLockoutRepository, "get_by_user_id", None)
    assert method is not None, "get_by_user_id missing from repository"
    assert inspect.iscoroutinefunction(method), "get_by_user_id must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "user_id"]


def test_user_lockout_repository_upsert_signature():
    from fief.repositories import UserLockoutRepository

    method = getattr(UserLockoutRepository, "upsert", None)
    assert method is not None, "upsert missing from repository"
    assert inspect.iscoroutinefunction(method), "upsert must be async"
    sig = inspect.signature(method)
    params = sig.parameters
    assert list(params.keys()) == ["self", "user_id", "failed_count", "locked_until"]
    # failed_count and locked_until are keyword-only
    assert params["failed_count"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["locked_until"].kind is inspect.Parameter.KEYWORD_ONLY


def test_user_lockout_repository_increment_and_apply_ladder_signature():
    from fief.repositories import UserLockoutRepository

    method = getattr(UserLockoutRepository, "increment_and_apply_ladder", None)
    assert method is not None, "increment_and_apply_ladder missing from repository"
    assert inspect.iscoroutinefunction(method), "increment_and_apply_ladder must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "user_id"]


def test_user_lockout_repository_clear_signature():
    from fief.repositories import UserLockoutRepository

    method = getattr(UserLockoutRepository, "clear", None)
    assert method is not None, "clear missing from repository"
    assert inspect.iscoroutinefunction(method), "clear must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "user_id"]
