import hashlib
import hmac

import requests
from cryptography.fernet import Fernet


TRUSTED_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def store_password(path, password, encryption_key):
    ciphertext = Fernet(encryption_key).encrypt(password.encode("utf-8")).decode("ascii")
    with open(path, "w", encoding="utf-8") as output:
        output.write(ciphertext)


def store_password_hash(path, password_hash):
    with open(path, "w", encoding="utf-8") as output:
        output.write(password_hash)


def download_verified(url):
    response = requests.get(url, timeout=5)
    payload = response.content
    actual_digest = hashlib.sha256(payload).hexdigest()
    if not hmac.compare_digest(actual_digest, TRUSTED_SHA256):
        raise ValueError("download integrity verification failed")
    exec(compile(payload.decode("utf-8"), url, "exec"), {"__builtins__": {}})


def read_configuration(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()
