from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class RequestBodyTooLargeError(RuntimeError):
    pass


class RequestBodyLimitMiddleware:
    def __init__(self, app: ASGIApp, max_body_bytes: int) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = _content_length(scope)
        if content_length is not None and content_length > self.max_body_bytes:
            await _send_too_large(scope, receive, send)
            return

        received_bytes = 0
        response_started = False

        async def limited_receive() -> Message:
            nonlocal received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > self.max_body_bytes:
                    raise RequestBodyTooLargeError
            return message

        async def tracked_send(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except RequestBodyTooLargeError:
            if response_started:
                raise
            await _send_too_large(scope, receive, send)


def _content_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers", []):
        if name.lower() != b"content-length":
            continue
        try:
            return int(value)
        except ValueError:
            return None
    return None


async def _send_too_large(scope: Scope, receive: Receive, send: Send) -> None:
    response = JSONResponse(
        {"detail": "요청 본문 크기가 허용 범위를 초과합니다."},
        status_code=413,
    )
    await response(scope, receive, send)
