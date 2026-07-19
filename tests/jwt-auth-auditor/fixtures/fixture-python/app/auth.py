import os
import time

from jose import jwt, JWTError

SECRET_KEY = os.environ.get("JWT_SECRET", "inventory-service-secret")
ALGORITHM = "HS256"
ACCESS_TOKEN_TTL_SECONDS = 15 * 60
ISSUER = "inventory.example"
AUDIENCE = "inventory-web"


def mint_access_token(user_id: int) -> str:
    now = int(time.time())
    payload = {
        "sub": str(user_id),
        "iss": ISSUER,
        "aud": AUDIENCE,
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_access_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM],
            issuer=ISSUER,
            audience=AUDIENCE,
        )
    except JWTError:
        return None
