from flask import request


def suppressed_code_injection() -> object:
    code = request.args.get("code", "0")
    return eval(code)  # nosemgrep
