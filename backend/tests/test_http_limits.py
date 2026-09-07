from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.http_limits import RequestBodyLimitMiddleware


def make_limited_app() -> FastAPI:
    limited_app = FastAPI()
    limited_app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=8)

    @limited_app.post("/")
    async def receive_body(request: Request) -> dict[str, int]:
        return {"size": len(await request.body())}

    return limited_app


def test_rejects_oversized_content_length_before_handler() -> None:
    response = TestClient(make_limited_app()).post("/", content=b"123456789")

    assert response.status_code == 413
    assert response.json() == {"detail": "요청 본문 크기가 허용 범위를 초과합니다."}


def test_counts_received_bytes_when_content_length_is_untrusted() -> None:
    response = TestClient(make_limited_app()).post(
        "/", content=b"123456789", headers={"content-length": "1"}
    )

    assert response.status_code == 413
