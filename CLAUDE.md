# Crotal

JWT authentication and role-based authorization library for FastAPI. Drop-in dependencies — no middleware, no manual token handling.

## Install

```bash
pip install git+https://github.com/draew6/crotal.git
```

## Usage via fastlet

Most services use crotal through fastlet. In fastlet-based services, always import from fastlet:

```python
# CORRECT — in fastlet-based services
from fastlet import User, Admin, OptionalUser, authenticated_client

# WRONG — do NOT import from crotal directly in fastlet-based services
from crotal import User  # breaks conventions
```

Import from crotal directly only when working inside the crotal repo itself or in projects that don't use fastlet.

## Env vars (all required)

```
AUTH_LOGIN_URL=    # OAuth2 token endpoint URL
JWT_SECRET=        # HMAC key for signing/verifying JWT tokens
COOKIE_SECRET=     # itsdangerous key for signing cookies
ROOT_DOMAIN=       # domain for cookie scope (e.g. example.com)
```

## Rules

- NEVER write custom auth middleware — use crotal's FastAPI dependencies
- NEVER decode JWTs manually — use `User`, `OptionalUser`, or role dependencies
- NEVER read Authorization headers directly — crotal handles Bearer + signed cookies automatically
- NEVER define your own user model for auth — use `UserInfo` from crotal
- NEVER hardcode role strings outside of crotal's dependencies — use `Admin`, `System`, etc.
- NEVER import from crotal in fastlet-based services — import from fastlet instead
- ALWAYS use `authenticated_client` from `crotal.testing` in tests — never forge tokens manually
- ALWAYS use `set_cookie` from `crotal.authentication` to set auth cookies — never set them raw

## Auth dependencies (use as FastAPI endpoint parameters)

```python
from crotal import User, OptionalUser, Admin, System, AdminOrSelf, SystemOrSelf, MustBeSelf
```

### Require authenticated user (returns 401 if missing)
```python
@app.get("/profile")
async def get_profile(user: User):
    # user is UserInfo(id=int, name=str, role="USER"|"SYSTEM"|"ADMIN", exp=datetime|None)
    return {"id": user.id, "name": user.name}
```

### Optional auth (None if not logged in)
```python
@app.get("/home")
async def home(user: OptionalUser):
    if user:
        return {"message": f"Hello {user.name}"}
    return {"message": "Hello guest"}
```

### Role gates
```python
# ADMIN only (403 for USER and SYSTEM)
@app.get("/admin")
async def admin_only(user: Admin): ...

# ADMIN or SYSTEM (403 for USER)
@app.delete("/cache")
async def system_level(user: System): ...
```

### Self-or-privileged (requires `user_id` path parameter)
```python
# User can access own resource, ADMIN can access any
@app.get("/users/{user_id}")
async def get_user(user_id: int, user: AdminOrSelf): ...

# User can access own resource, ADMIN or SYSTEM can access any
@app.put("/users/{user_id}/settings")
async def update_settings(user_id: int, user: SystemOrSelf): ...
```

### Manual self-check (for non-path-parameter cases)
```python
@app.put("/transfer")
async def transfer(sender_id: int, receiver_id: int, user: User):
    MustBeSelf(user, [sender_id])  # 403 unless user.id == sender_id (or ADMIN/SYSTEM)
```

## Roles

Three roles, ordered by privilege: `USER` < `SYSTEM` < `ADMIN`.

| Dependency | USER | SYSTEM | ADMIN |
|---|---|---|---|
| `User` | yes | yes | yes |
| `System` | no | yes | yes |
| `Admin` | no | no | yes |
| `AdminOrSelf` | own only | no | yes |
| `SystemOrSelf` | own only | yes | yes |

## Token creation (for auth services, not for consumers)

```python
from crotal.tokens import create_access_token, create_system_access_token, create_token

# JWT access token (15min expiry)
token = create_access_token(user_id=1, role="USER", name="alice")

# System-level token for service-to-service calls
system_token = create_system_access_token()

# Random hex token (for refresh tokens, API keys)
raw_token = create_token()
```

## Cookie management

```python
from crotal.authentication import set_cookie

@app.post("/login")
async def login(response: Response):
    set_cookie(response, "access_token", access_token)
    set_cookie(response, "refresh_token", refresh_token)
    # Sets secure, httponly, samesite=none cookies signed with COOKIE_SECRET
    # Scoped to ROOT_DOMAIN
```

## Testing

```python
from starlette.testclient import TestClient
from crotal.testing import authenticated_client

client = authenticated_client(TestClient(app), id=5, name="alice", role="ADMIN")
resp = client.get("/admin")
assert resp.status_code == 200

# Defaults: id=1, name="testuser", role="USER"
basic_client = authenticated_client(TestClient(app))
```

## Token resolution order

1. `Authorization: Bearer <jwt>` header (checked first)
2. Signed cookies (`access_token`, `refresh_token` signed with itsdangerous)

If both exist, Bearer wins. If token is expired, falls through to cookies. If both expired → `None` (401 for `User`, `None` for `OptionalUser`).

## Architecture

Dependency chain: `config.py` → `authentication.py` → `authorization.py`. No circular imports.

- `config.py` — `Settings` via pydantic-settings, cached with `@lru_cache`
- `models.py` — `AuthTokens(access_token, refresh_token)`, `UserInfo(id, name, role, exp)`
- `authentication.py` — token extraction, verification, `User`/`OptionalUser` dependencies
- `authorization.py` — role gates, `Admin`/`System`/`AdminOrSelf`/`SystemOrSelf`/`MustBeSelf`
- `tokens.py` — token creation utilities
- `testing.py` — `authenticated_client` test helper

## Running tests

```bash
pytest tests/ -v
```

Requires env vars: `AUTH_LOGIN_URL`, `JWT_SECRET`, `COOKIE_SECRET`, `ROOT_DOMAIN`.