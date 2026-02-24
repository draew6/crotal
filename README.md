# crotal

FastAPI authentication and role-based authorization via JWT.

## Install

```bash
pip install crotal
```

## Usage

### Require an authenticated user (401 if missing)

```python
from fastapi import FastAPI
from crotal import User

app = FastAPI()

@app.get("/profile")
async def get_profile(user: User):
    return {"id": user.id, "name": user.name, "role": user.role}
```

### Optional authentication (None if not logged in)

```python
from crotal import OptionalUser

@app.get("/home")
async def home(user: OptionalUser):
    if user:
        return {"message": f"Hello {user.name}"}
    return {"message": "Hello guest"}
```

### Role-based authorization

```python
from crotal import Admin, System

@app.get("/admin/dashboard")
async def admin_dashboard(user: Admin):
    # Only ADMIN role gets through, others get 403
    return {"admin": user.name}

@app.delete("/cache")
async def clear_cache(user: System):
    # ADMIN and SYSTEM roles allowed, USER gets 403
    ...
```

### Self-or-privileged access

```python
from crotal import AdminOrSelf, SystemOrSelf

@app.get("/users/{user_id}")
async def get_user(user_id: int, user: AdminOrSelf):
    # User can access their own resource, ADMIN can access any
    ...

@app.put("/users/{user_id}/settings")
async def update_settings(user_id: int, user: SystemOrSelf):
    # User can update their own, ADMIN and SYSTEM can update any
    ...
```

### Manual self-check

```python
from crotal import User, MustBeSelf

@app.put("/transfer")
async def transfer(sender_id: int, receiver_id: int, user: User):
    MustBeSelf(user, [sender_id])  # 403 unless user is sender (or ADMIN/SYSTEM)
    ...
```

## Testing utility

Crotal provides a test helper for consuming projects. Import from `crotal.testing` and pass your `TestClient` to get an authenticated client with a Bearer token injected:

```python
from starlette.testclient import TestClient
from crotal.testing import authenticated_client

client = authenticated_client(TestClient(app), id=5, name="alice", role="ADMIN")
resp = client.get("/admin/dashboard")
assert resp.status_code == 200
```

All parameters (`id`, `name`, `role`) are optional and default to a regular user.

## Roles

| Role     | Description                     |
|----------|---------------------------------|
| `USER`   | Regular user                    |
| `SYSTEM` | Service-level access            |
| `ADMIN`  | Full access, bypasses all gates |

## Token sources

Crotal accepts JWT tokens from two sources (bearer header takes precedence):

1. **Bearer header**: `Authorization: Bearer <jwt>`
2. **Signed cookies**: `access_token` and `refresh_token` cookies signed with itsdangerous