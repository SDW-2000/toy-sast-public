from fastapi import Depends, FastAPI, HTTPException
from fastapi_limiter.depends import RateLimiter

app = FastAPI()


class Document:
    query = None


def current_user_id() -> int:
    return 7


@app.get("/documents/{document_id}")
def get_document(document_id: int):
    document = Document.query.get(document_id)
    if document.owner_id != current_user_id():
        raise HTTPException(status_code=403)
    return document


@app.post(
    "/login",
    dependencies=[Depends(RateLimiter(times=5, seconds=60))],
)
def login():
    return {"authenticated": False}
