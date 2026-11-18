"""Passphrase hashing. Argon2id via argon2-cffi. The passphrase is never logged."""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_hasher = PasswordHasher()


def hash_passphrase(passphrase: str) -> str:
    return _hasher.hash(passphrase)


def verify_passphrase(passphrase: str, encoded: str) -> bool:
    try:
        return _hasher.verify(encoded, passphrase)
    except VerifyMismatchError:
        return False
