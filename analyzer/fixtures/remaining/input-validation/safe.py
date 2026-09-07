from typing import Any

from flask import Response, request
from ldap.filter import escape_filter_chars


def find_account(cursor: Any) -> object:
    account = request.args.get("account", "")
    return cursor.execute("SELECT id FROM accounts WHERE name = %s", (account,))


def find_directory_entry(connection: Any) -> object:
    username = escape_filter_chars(request.form.get("username", ""))
    ldap_filter = f"(uid={username})"
    return connection.search_s("ou=people,dc=example,dc=invalid", 2, ldap_filter)


def sanitize_header(value: str) -> str:
    if "\r" in value or "\n" in value:
        raise ValueError("header contains a line break")
    return value


def redirect_with_validated_header() -> Response:
    destination = sanitize_header(request.args.get("next", "/"))
    response = Response(status=302)
    response.headers["Location"] = destination
    return response
