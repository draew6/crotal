from fastapi import FastAPI
from starlette.testclient import TestClient

from crotal.authentication import User, OptionalUser
from crotal.testing import authenticated_client

app = FastAPI()


@app.get("/me")
async def me(user: User):
    return {"id": user.id, "name": user.name, "role": user.role}


@app.get("/optional")
async def optional(user: OptionalUser):
    if user:
        return {"id": user.id, "name": user.name, "role": user.role}
    return {"user": None}


def test_authenticated_client_injects_bearer():
    client = authenticated_client(TestClient(app), id=42, name="alice", role="ADMIN")
    resp = client.get("/me")
    assert resp.status_code == 200
    assert resp.json() == {"id": 42, "name": "alice", "role": "ADMIN"}


def test_authenticated_client_defaults():
    client = authenticated_client(TestClient(app))
    resp = client.get("/me")
    assert resp.status_code == 200
    assert resp.json() == {"id": 1, "name": "testuser", "role": "USER"}


def test_unauthenticated_client_gets_401():
    client = TestClient(app)
    resp = client.get("/me")
    assert resp.status_code == 401
