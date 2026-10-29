import bcrypt
import pytest

from fief.crypto.password import PasswordHelper


@pytest.mark.parametrize("password", ["a secure test password", "a" * 100, "🔐" * 30])
def test_new_passwords_use_argon2_and_preserve_the_full_password(password):
    helper = PasswordHelper()
    hashed = helper.hash(password)
    assert hashed.startswith("$argon2id$")
    assert helper.verify_and_update(password, hashed) == (True, None)
    assert helper.verify_and_update(password + "different suffix", hashed) == (
        False,
        None,
    )


@pytest.mark.parametrize("password", ["legacy password", "a" * 100, "密" * 25])
def test_legacy_bcrypt_passwords_are_verified_and_upgraded(password):
    # bcrypt 4 and earlier truncated at 72 bytes, including multibyte input.
    hashed = bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt()).decode()
    helper = PasswordHelper()
    assert helper.verify_and_update("wrong password", hashed) == (False, None)
    valid, upgraded = helper.verify_and_update(password, hashed)
    assert valid
    assert upgraded.startswith("$argon2id$")
    assert helper.verify_and_update(password, upgraded) == (True, None)


def test_existing_argon2_password_is_still_accepted():
    helper = PasswordHelper()
    hashed = helper.hash("already migrated")
    assert helper.verify_and_update("already migrated", hashed) == (True, None)
