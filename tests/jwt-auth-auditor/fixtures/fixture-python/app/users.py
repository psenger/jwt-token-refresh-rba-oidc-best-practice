from passlib.hash import bcrypt

_USERS = [
    {"id": 1, "email": "ada@example.com", "password_hash": bcrypt.hash("placeholder")},
]


def find_user_by_credentials(email: str, password: str) -> dict | None:
    for user in _USERS:
        if user["email"] == email and bcrypt.verify(password, user["password_hash"]):
            return user
    return None
