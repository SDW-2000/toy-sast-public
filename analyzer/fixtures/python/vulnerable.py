import hashlib
import os
import pickle
import random
import traceback

import requests
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import request
from lxml import etree


def evaluate() -> object:
    code = f"({request.args.get('expression', '0')})"
    return eval(code)


def run_command() -> int:
    command = "printf " + request.form.get("message", "")
    return os.system(command)


def parse_unsafe_xml(xml_document: str) -> object:
    parser = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(xml_document, parser=parser)


def fetch_user_url() -> object:
    target_url = f"{request.json.get('target_url')}"
    return requests.get(target_url)


def expose_file(report_path: str) -> None:
    os.chmod(report_path, 0o666)


def weak_hash(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()


def hardcoded_credential() -> str:
    database_password = "prod-secret-12345"
    return database_password


def short_key() -> object:
    return rsa.generate_private_key(public_exponent=65537, key_size=1536)


def predictable_token() -> int:
    auth_token = random.randint(100000, 999999)
    return auth_token


def fetch_without_certificate_check() -> object:
    return requests.get("https://api.example.invalid", verify=False)


def insecure_cookie(response: object) -> None:
    response.set_cookie("session", "value", secure=True, max_age=86400)


# api_key = "development-secret!@#$%^&*()"
def leaked_comment_marker() -> str:
    return "comment above contains a credential"


def hash_password(password: bytes) -> str:
    return hashlib.sha256(password).hexdigest()


def spin_forever() -> None:
    while True:
        print("still running")


def expose_failure() -> str:
    return traceback.format_exc()


def ignore_value_error() -> None:
    try:
        int("not-an-integer")
    except ValueError:
        pass


def catch_everything() -> None:
    try:
        raise RuntimeError("failure")
    except Exception as error:
        print("operation failed", error)


def deserialize(payload: bytes) -> object:
    return pickle.loads(payload)


def left_over_debugger() -> None:
    breakpoint()
