from app.auth import (
    hash_invitation_token,
    hash_password,
    hash_session_token,
    is_valid_email,
    normalize_email,
    verify_password,
)


def test_password_hash_round_trip_and_rejects_wrong_password() -> None:
    candidate = "a-long-test-password"
    password_hash = hash_password(candidate)

    assert password_hash != candidate
    assert verify_password(password_hash, candidate) is True
    assert verify_password(password_hash, "wrong-password") is False


def test_invalid_password_hash_fails_closed() -> None:
    assert verify_password("not-an-argon2-hash", "password") is False
    assert verify_password(None, "password") is False


def test_session_hash_is_secret_bound_and_deterministic() -> None:
    first = hash_session_token("opaque-token", "secret-a")

    assert first == hash_session_token("opaque-token", "secret-a")
    assert first != hash_session_token("opaque-token", "secret-b")
    assert len(first) == 64


def test_invitation_hash_is_purpose_and_secret_bound() -> None:
    invitation_hash = hash_invitation_token("opaque-token", "secret-a")

    assert invitation_hash == hash_invitation_token("opaque-token", "secret-a")
    assert invitation_hash != hash_invitation_token("opaque-token", "secret-b")
    assert invitation_hash != hash_session_token("opaque-token", "secret-a")


def test_email_normalization_trims_and_casefolds() -> None:
    assert normalize_email("  Admin@EXAMPLE.com  ") == "admin@example.com"
    assert is_valid_email("admin@example.com") is True
    assert is_valid_email("invalid") is False
