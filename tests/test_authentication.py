import pytest
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from jose import jwt
from itsdangerous import Signer

from crotal.authentication import OptionalUser, User
from crotal.config import get_settings

USER_PAYLOAD = {"id": 1, "name": "testuser", "role": "USER"}

app = FastAPI()


@app.get("/optional")
async def optional_route(user: OptionalUser):
    if user:
        return {"id": user.id, "name": user.name, "role": user.role}
    return {"user": None}


@app.get("/required")
async def required_route(user: User):
    return {"id": user.id, "name": user.name, "role": user.role}


def make_jwt(payload: dict, expired: bool = False) -> str:
    data = {**payload}
    if expired:
        data["exp"] = datetime.now(timezone.utc) - timedelta(hours=1)
    else:
        data["exp"] = datetime.now(timezone.utc) + timedelta(hours=1)
    return jwt.encode(data, get_settings().jwt_secret, algorithm="HS256")


def sign_cookie(value: str) -> str:
    return Signer(get_settings().cookie_secret).sign(value).decode()


@pytest.fixture
def client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


# --- No credentials ---


@pytest.mark.asyncio
async def test_optional_no_auth(client):
    resp = await client.get("/optional")
    assert resp.status_code == 200
    assert resp.json() == {"user": None}


@pytest.mark.asyncio
async def test_required_no_auth_returns_401(client):
    resp = await client.get("/required")
    assert resp.status_code == 401


# --- Bearer token ---


@pytest.mark.asyncio
async def test_bearer_valid(client):
    token = make_jwt(USER_PAYLOAD)
    resp = await client.get("/optional", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["id"] == 1
    assert resp.json()["role"] == "USER"


@pytest.mark.asyncio
async def test_bearer_expired(client):
    token = make_jwt(USER_PAYLOAD, expired=True)
    resp = await client.get("/optional", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json() == {"user": None}


@pytest.mark.asyncio
async def test_required_with_bearer(client):
    token = make_jwt(USER_PAYLOAD)
    resp = await client.get("/required", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert resp.json()["id"] == 1


# --- Cookie tokens ---


def make_signed_cookies(access_payload: dict, expired: bool = False) -> dict:
    access = make_jwt(access_payload, expired=expired)
    refresh = make_jwt({"refresh": True})
    return {
        "access_token": sign_cookie(access),
        "refresh_token": sign_cookie(refresh),
    }


@pytest.mark.asyncio
async def test_cookie_valid(client):
    cookies = make_signed_cookies(USER_PAYLOAD)
    resp = await client.get("/optional", cookies=cookies)
    assert resp.status_code == 200
    assert resp.json()["id"] == 1
    assert resp.json()["role"] == "USER"


@pytest.mark.asyncio
async def test_cookie_bad_signature(client):
    access = make_jwt(USER_PAYLOAD)
    refresh = make_jwt({"refresh": True})
    cookies = {"access_token": access, "refresh_token": refresh}  # not signed
    resp = await client.get("/optional", cookies=cookies)
    assert resp.status_code == 200
    assert resp.json() == {"user": None}


@pytest.mark.asyncio
async def test_cookie_expired_jwt(client):
    cookies = make_signed_cookies(USER_PAYLOAD, expired=True)
    resp = await client.get("/optional", cookies=cookies)
    assert resp.status_code == 200
    assert resp.json() == {"user": None}


@pytest.mark.asyncio
async def test_cookie_missing_refresh_token(client):
    access = make_jwt(USER_PAYLOAD)
    cookies = {"access_token": sign_cookie(access)}
    resp = await client.get("/optional", cookies=cookies)
    assert resp.status_code == 200
    assert resp.json() == {"user": None}


# --- Bearer takes precedence ---


@pytest.mark.asyncio
async def test_bearer_takes_precedence_over_cookie(client):
    bearer_token = make_jwt({"id": 1, "name": "bearer_user", "role": "ADMIN"})
    cookies = make_signed_cookies({"id": 2, "name": "cookie_user", "role": "USER"})
    resp = await client.get(
        "/optional",
        headers={"Authorization": f"Bearer {bearer_token}"},
        cookies=cookies,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "bearer_user"


@pytest.mark.asyncio
async def test_falls_back_to_cookie_when_bearer_expired(client):
    bearer_token = make_jwt(USER_PAYLOAD, expired=True)
    cookies = make_signed_cookies({"id": 2, "name": "cookie_user", "role": "ADMIN"})
    resp = await client.get(
        "/optional",
        headers={"Authorization": f"Bearer {bearer_token}"},
        cookies=cookies,
    )
    assert resp.status_code == 200
    assert resp.json()["name"] == "cookie_user"
