import hashlib
import hmac
import re
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError

SESSION_COOKIE_NAME = "toy_sast_session"
_PASSWORD_HASHER = PasswordHasher()
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash(secrets.token_urlsafe(32))
_EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def normalize_email(email: str) -> str:
    return email.strip().casefold()


def is_valid_email(email: str) -> bool:
    return _EMAIL_PATTERN.fullmatch(email) is not None


def hash_password(password: str) -> str:
    return _PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _PASSWORD_HASHER.verify(password_hash or _DUMMY_PASSWORD_HASH, password)
    except (InvalidHashError, VerifyMismatchError):
        return False


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


def hash_session_token(token: str, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), token.encode("utf-8"), hashlib.sha256).hexdigest()


def new_invitation_token() -> str:
    return secrets.token_urlsafe(32)


def hash_invitation_token(token: str, secret: str) -> str:
    message = f"user-invitation:{token}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()
