# crotal

JWT authentication and role-based authorization for FastAPI. Drop-in dependencies — no middleware, no manual token handling.

## Install

```bash
pip install git+https://github.com/draew6/crotal.git

```

Requires Python 3.13+.

## Quick example

```python
from fastapi import FastAPI
from crotal import User, Admin, OptionalUser

app = FastAPI()

@app.get("/profile")
async def get_profile(user: User):
    return {"id": user.id, "name": user.name, "role": user.role}

@app.get("/admin")
async def admin_only(user: Admin):
    return {"admin": user.name}
```

## Dependencies

| Dependency | Who gets through |
|---|---|
| `User` | Any authenticated user |
| `OptionalUser` | Anyone (None if not logged in) |
| `Admin` | ADMIN only |
| `System` | ADMIN, SYSTEM |
| `AdminOrSelf` | ADMIN, or user matching `user_id` path param |
| `SystemOrSelf` | ADMIN, SYSTEM, or user matching `user_id` path param |
| `MustBeSelf(user, [ids])` | Manual self-check (ADMIN/SYSTEM bypass) |

## Env vars

```
AUTH_LOGIN_URL=    # OAuth2 token endpoint
JWT_SECRET=        # JWT signing key
COOKIE_SECRET=     # Cookie signing key (itsdangerous)
ROOT_DOMAIN=       # Cookie domain scope
```

## Documentation

See [CLAUDE.md](./CLAUDE.md) for detailed usage patterns, rules, and architecture.

## Used via fastlet

Most services use crotal through [fastlet](https://github.com/draew6/fastlet2). In that case, import from fastlet instead of crotal directly.