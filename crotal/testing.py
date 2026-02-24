from datetime import datetime, timedelta, timezone

from jose import jwt
from starlette.testclient import TestClient

from .config import get_settings
from .models import UserInfo


def authenticated_client(
    client: TestClient,
    *,
    id: int = 1,
    name: str = "testuser",
    role: str = "USER",
) -> TestClient:
    payload = {
        "id": id,
        "name": name,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(hours=1),
    }
    token = jwt.encode(payload, get_settings().jwt_secret, algorithm="HS256")
    client.headers["Authorization"] = f"Bearer {token}"
    return client
