import hashlib
import os
import secrets

import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from defusedxml import ElementTree


def evaluate_fixed_code() -> object:
    trusted_code = "40 + 2"
    return eval(trusted_code)


def calculate(left: int, right: int) -> int:
    return left + right


def fixed_command() -> int:
    trusted_command = "printf '%s' hello"
    return os.system(trusted_command)


def parse_safe_xml(xml_document: str) -> object:
    return ElementTree.fromstring(xml_document)


def fetch_allowlisted_service() -> object:
    trusted_url = "https://api.example.invalid/health"
    return requests.get(trusted_url, timeout=3)


def protect_file(report_path: str) -> None:
    os.chmod(report_path, 0o600)


def strong_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def configured_credential() -> str | None:
    return os.environ.get("DATABASE_PASSWORD")


def strong_key() -> object:
    return rsa.generate_private_key(public_exponent=65537, key_size=3072)


def secure_token() -> str:
    return secrets.token_urlsafe(32)


def verified_request() -> object:
    return requests.get("https://api.example.invalid", verify=True, timeout=3)


def secure_cookie(response: object) -> None:
    response.set_cookie("session", "value", secure=True, httponly=True, max_age=0)


def salted_password_hash(password: bytes, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password, salt, 200_000)


def bounded_work() -> None:
    for attempt in range(3):
        print(attempt)


def loop_with_break() -> None:
    while True:
        break


def loop_with_return() -> None:
    while True:
        return


def generic_failure() -> str:
    return "request failed"


def handle_value_error() -> None:
    try:
        int("not-an-integer")
    except ValueError as error:
        print("invalid integer", error)


def parse_json(payload: str) -> str:
    return payload
