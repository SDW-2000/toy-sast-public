import requests


def store_password(path, password):
    with open(path, "w", encoding="utf-8") as output:
        output.write(password)


def download_and_execute(url):
    exec(requests.get(url, timeout=5).text)


def read_configuration(path):
    handle = open(path, encoding="utf-8")
    return handle.read()
