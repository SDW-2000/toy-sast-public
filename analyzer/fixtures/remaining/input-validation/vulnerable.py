from flask import Response, request


def find_account(cursor: object) -> object:
    account = request.args.get("account", "")
    query = f"SELECT id FROM accounts WHERE name = '{account}'"
    return cursor.execute(query)


def find_directory_entry(connection: object) -> object:
    username = request.form.get("username", "")
    ldap_filter = "(uid=" + username + ")"
    return connection.search_s("ou=people,dc=example,dc=invalid", 2, ldap_filter)


def redirect_with_untrusted_header() -> Response:
    response = Response(status=302)
    response.headers["Location"] = request.args.get("next", "/")
    return response
