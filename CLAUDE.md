# Crotal

Internal FastAPI authentication/authorization library using JWT tokens with role-based access control.

## Structure

```
crotal/
  config.py          - constants (JWT_SECRET, COOKIE_SECRET, AUTH_LOGIN_URL)
  models.py          - Pydantic models (AuthTokens, UserInfo)
  authentication.py  - token extraction, verification, user resolution (OptionalUser, User)
  authorization.py   - role-based access control (Admin, System, AdminOrSelf, SystemOrSelf, MustBeSelf)
  __init__.py        - re-exports public API
```

## Architecture

Dependency chain is linear: `authentication.py` -> `authorization.py`. No circular imports.

Authentication supports two token sources: Bearer header (JWT) and signed cookies (itsdangerous + JWT). Bearer takes precedence.

Roles: USER, SYSTEM, ADMIN. ADMIN is the highest privilege, SYSTEM is mid-tier.

## Testing

```
.venv/bin/pytest tests/ -v
```

- `test_authentication.py` - integration tests using FastAPI TestClient
- `test_authorization.py` - direct unit tests on authorization functions