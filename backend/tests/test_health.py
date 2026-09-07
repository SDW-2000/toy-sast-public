import os

os.environ.setdefault("DATABASE_URL", "postgresql://unused:unused@localhost/unused")
os.environ.setdefault("SESSION_SECRET", "test-only-secret")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def test_health() -> None:
    response = TestClient(app).get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
