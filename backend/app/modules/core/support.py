from fastapi import HTTPException


def safe_part(value: str) -> str:
    cleaned = "".join(
        char if char.isalnum() or char in "._-" else "_" for char in value
    ).strip("._")
    if not cleaned:
        raise HTTPException(400, "Unsafe path component")
    return cleaned[:120]


def need(db, model, ident: int):
    row = db.get(model, ident)
    if not row:
        raise HTTPException(404, "Not found")
    return row
