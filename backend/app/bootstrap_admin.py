"""Create an initial local administrator without exposing a password in arguments."""

import argparse
import getpass
from uuid import uuid4

from app.auth import hash_password, is_valid_email, normalize_email
from app.config import get_settings
from app.database import Database, UserEmailAlreadyExistsError
from app.schemas import UserRole


def main() -> None:
    parser = argparse.ArgumentParser(description="Create a TOY SAST administrator")
    parser.add_argument("--email", required=True, help="Administrator email address")
    args = parser.parse_args()

    email = normalize_email(args.email)
    if not is_valid_email(email):
        raise SystemExit("Enter a valid administrator email address.")
    password = getpass.getpass("Password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if len(password) < 12:
        raise SystemExit("Password must contain at least 12 characters.")
    if password != confirmation:
        raise SystemExit("Passwords do not match.")

    settings = get_settings()
    database = Database(settings.database_url, cursor_secret=settings.session_secret)
    try:
        user = database.create_user(
            str(uuid4()),
            email=email,
            password_hash=hash_password(password),
            role=UserRole.ADMIN,
        )
    except UserEmailAlreadyExistsError as exc:
        raise SystemExit(f"A user with {email} already exists.") from exc
    print(f"Created administrator: {user.email}")


if __name__ == "__main__":
    main()
