import secrets
from datetime import datetime, UTC, timedelta
from jose import jwt
from .config import get_settings


def create_token() -> str:
    return secrets.token_hex(20)


def create_access_token(user_id: int, role: str, name: str) -> str:
    return jwt.encode(
        {"id": user_id, "role": role, "name": name}
        | {"exp": datetime.now(UTC) + timedelta(minutes=15)},
        get_settings().jwt_secret,
        algorithm="HS256",
    )


def create_system_access_token(system_name: str = "SYSTEM") -> str:
    return create_access_token(0, "SYSTEM", system_name)
