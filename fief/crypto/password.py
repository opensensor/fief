import secrets

from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher


class LegacyBcryptHasher(BcryptHasher):
    """Verify existing hashes with the byte limit used by bcrypt before v5."""

    def verify(self, password: str | bytes, hash: str | bytes) -> bool:
        password_bytes = password.encode("utf-8") if isinstance(password, str) else password
        return super().verify(password_bytes[:72], hash)


class PasswordHelper:
    def __init__(self) -> None:
        # New passwords use Argon2id. Successful legacy logins upgrade their
        # bcrypt hashes without requiring a password reset.
        self.password_hash = PasswordHash((Argon2Hasher(), LegacyBcryptHasher()))

    def verify_and_update(
        self, plain_password: str, hashed_password: str
    ) -> tuple[bool, str | None]:
        return self.password_hash.verify_and_update(plain_password, hashed_password)

    def hash(self, password: str) -> str:
        return self.password_hash.hash(password)

    def generate(self) -> str:
        return secrets.token_urlsafe()


password_helper = PasswordHelper()
