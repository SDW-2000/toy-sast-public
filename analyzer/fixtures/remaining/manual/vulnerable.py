from fastapi import FastAPI

app = FastAPI()


class Document:
    query = None


@app.get("/documents/{document_id}")
def get_document(document_id: int):
    return Document.query.get(document_id)


@app.post("/login")
def login():
    return {"authenticated": False}
