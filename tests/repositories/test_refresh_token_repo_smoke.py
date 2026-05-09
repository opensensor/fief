"""Smoke tests for the RefreshTokenRepository (UX-1 T7).

These assertions don't talk to the database — they only verify the
repository class is importable, exposes the expected methods with the
right signatures, and inherits from the project's BaseRepository
pattern. Real CRUD coverage lives with the service-level tests in T10
and beyond.
"""

from __future__ import annotations

import inspect


def test_refresh_token_repository_importable_from_package():
    from fief.repositories import RefreshTokenRepository

    assert RefreshTokenRepository is not None


def test_refresh_token_repository_subclasses_base_repository():
    from fief.repositories import RefreshTokenRepository
    from fief.repositories.base import BaseRepository

    assert issubclass(RefreshTokenRepository, BaseRepository)


def test_refresh_token_repository_binds_correct_model():
    from fief.models import RefreshToken
    from fief.repositories import RefreshTokenRepository

    assert RefreshTokenRepository.model is RefreshToken


def test_refresh_token_repository_get_by_token_signature():
    from fief.repositories import RefreshTokenRepository

    method = getattr(RefreshTokenRepository, "get_by_token", None)
    assert method is not None, "get_by_token missing from repository"
    assert inspect.iscoroutinefunction(method), "get_by_token must be async"


def test_refresh_token_repository_list_by_user_id_signature():
    from fief.repositories import RefreshTokenRepository

    method = getattr(RefreshTokenRepository, "list_by_user_id", None)
    assert method is not None, "list_by_user_id missing from repository"
    assert inspect.iscoroutinefunction(method), "list_by_user_id must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "user_id"]


def test_refresh_token_repository_delete_by_id_for_user_signature():
    from fief.repositories import RefreshTokenRepository

    method = getattr(RefreshTokenRepository, "delete_by_id_for_user", None)
    assert method is not None, "delete_by_id_for_user missing from repository"
    assert inspect.iscoroutinefunction(method), "delete_by_id_for_user must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "token_id", "user_id"]


def test_refresh_token_repository_delete_all_except_for_user_signature():
    from fief.repositories import RefreshTokenRepository

    method = getattr(RefreshTokenRepository, "delete_all_except_for_user", None)
    assert method is not None, "delete_all_except_for_user missing from repository"
    assert inspect.iscoroutinefunction(method), (
        "delete_all_except_for_user must be async"
    )
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "user_id", "except_ids"]


def test_refresh_token_repository_touch_last_seen_signature():
    from fief.repositories import RefreshTokenRepository

    method = getattr(RefreshTokenRepository, "touch_last_seen", None)
    assert method is not None, "touch_last_seen missing from repository"
    assert inspect.iscoroutinefunction(method), "touch_last_seen must be async"
    sig = inspect.signature(method)
    params = sig.parameters
    assert list(params.keys()) == ["self", "token_id", "last_seen_at", "last_seen_ip"]
    # last_seen_at and last_seen_ip are keyword-only
    assert params["last_seen_at"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["last_seen_ip"].kind is inspect.Parameter.KEYWORD_ONLY
