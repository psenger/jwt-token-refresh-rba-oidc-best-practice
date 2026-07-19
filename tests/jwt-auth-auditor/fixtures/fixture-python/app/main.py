from fastapi import FastAPI, Depends, HTTPException, Response, Cookie
from passlib.hash import bcrypt

from app.auth import mint_access_token, verify_access_token, ACCESS_TOKEN_TTL_SECONDS
from app.users import find_user_by_credentials

app = FastAPI()


@app.post("/api/login")
async def login(response: Response, email: str, password: str):
    user = find_user_by_credentials(email, password)
    if user is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    token = mint_access_token(user["id"])
    response.set_cookie(
        key="access_token",
        value=token,
        max_age=ACCESS_TOKEN_TTL_SECONDS,
        httponly=True,
        secure=True,
        samesite="strict",
    )
    response.headers["Cache-Control"] = "no-store"
    return {"ok": True}


async def require_auth(access_token: str | None = Cookie(default=None)) -> dict:
    if access_token is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    payload = verify_access_token(access_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Authentication failed")
    return payload


@app.get("/api/items")
async def list_items(user: dict = Depends(require_auth)):
    return {"items": [], "owner": user["sub"]}
