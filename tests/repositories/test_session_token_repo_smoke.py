"""Smoke tests for the SessionTokenRepository (UX-1 T6).

These assertions don't talk to the database — they only verify the
repository class is importable, exposes the expected methods with the
right signatures, and inherits from the project's BaseRepository
pattern. Real CRUD coverage lives with the service-level tests in
later UX-1 tasks.
"""

from __future__ import annotations

import inspect


def test_session_token_repository_importable_from_package():
    from fief.repositories import SessionTokenRepository

    assert SessionTokenRepository is not None


def test_session_token_repository_subclasses_base_repository():
    from fief.repositories import SessionTokenRepository
    from fief.repositories.base import BaseRepository

    assert issubclass(SessionTokenRepository, BaseRepository)


def test_session_token_repository_binds_correct_model():
    from fief.models import SessionToken
    from fief.repositories import SessionTokenRepository

    assert SessionTokenRepository.model is SessionToken


def test_session_token_repository_list_by_user_id_signature():
    from fief.repositories import SessionTokenRepository

    method = getattr(SessionTokenRepository, "list_by_user_id", None)
    assert method is not None, "list_by_user_id missing from repository"
    assert inspect.iscoroutinefunction(method), "list_by_user_id must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "user_id"]


def test_session_token_repository_delete_by_id_for_user_signature():
    from fief.repositories import SessionTokenRepository

    method = getattr(SessionTokenRepository, "delete_by_id_for_user", None)
    assert method is not None, "delete_by_id_for_user missing from repository"
    assert inspect.iscoroutinefunction(method), "delete_by_id_for_user must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "token_id", "user_id"]


def test_session_token_repository_delete_all_except_for_user_signature():
    from fief.repositories import SessionTokenRepository

    method = getattr(SessionTokenRepository, "delete_all_except_for_user", None)
    assert method is not None, "delete_all_except_for_user missing from repository"
    assert inspect.iscoroutinefunction(method), "delete_all_except_for_user must be async"
    sig = inspect.signature(method)
    assert list(sig.parameters.keys()) == ["self", "user_id", "except_ids"]


def test_session_token_repository_touch_last_seen_signature():
    from fief.repositories import SessionTokenRepository

    method = getattr(SessionTokenRepository, "touch_last_seen", None)
    assert method is not None, "touch_last_seen missing from repository"
    assert inspect.iscoroutinefunction(method), "touch_last_seen must be async"
    sig = inspect.signature(method)
    params = sig.parameters
    assert list(params.keys()) == ["self", "token_id", "last_seen_at", "last_seen_ip"]
    # last_seen_at and last_seen_ip are keyword-only
    assert params["last_seen_at"].kind is inspect.Parameter.KEYWORD_ONLY
    assert params["last_seen_ip"].kind is inspect.Parameter.KEYWORD_ONLY


def test_session_token_repository_get_by_token_still_present():
    """Sanity check: pre-existing method shouldn't have been removed."""
    from fief.repositories import SessionTokenRepository

    method = getattr(SessionTokenRepository, "get_by_token", None)
    assert method is not None, "get_by_token missing from repository"
    assert inspect.iscoroutinefunction(method)
