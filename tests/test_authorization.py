import pytest
from fastapi import HTTPException

from crotal.authorization import (
    authorize_admin,
    authorize_system,
    authorize_admin_or_self,
    authorize_system_or_self,
    MustBeSelf,
)
from crotal.models import UserInfo


def make_user(role: str, id: int = 1) -> UserInfo:
    return UserInfo(id=id, name="test", role=role)


# --- authorize_admin ---


@pytest.mark.asyncio
async def test_admin_allows_admin():
    user = make_user("ADMIN")
    assert await authorize_admin(user) == user


@pytest.mark.asyncio
async def test_admin_rejects_user():
    with pytest.raises(HTTPException) as exc:
        await authorize_admin(make_user("USER"))
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_rejects_system():
    with pytest.raises(HTTPException) as exc:
        await authorize_admin(make_user("SYSTEM"))
    assert exc.value.status_code == 403


# --- authorize_system ---


@pytest.mark.asyncio
async def test_system_allows_admin():
    user = make_user("ADMIN")
    assert await authorize_system(user) == user


@pytest.mark.asyncio
async def test_system_allows_system():
    user = make_user("SYSTEM")
    assert await authorize_system(user) == user


@pytest.mark.asyncio
async def test_system_rejects_user():
    with pytest.raises(HTTPException) as exc:
        await authorize_system(make_user("USER"))
    assert exc.value.status_code == 403


# --- MustBeSelf ---


def test_must_be_self_admin_bypasses():
    MustBeSelf(make_user("ADMIN", id=1), [999])


def test_must_be_self_system_bypasses():
    MustBeSelf(make_user("SYSTEM", id=1), [999])


def test_must_be_self_matching_user():
    MustBeSelf(make_user("USER", id=1), [1])


def test_must_be_self_non_matching_user():
    with pytest.raises(HTTPException) as exc:
        MustBeSelf(make_user("USER", id=1), [2])
    assert exc.value.status_code == 403


def test_must_be_self_multiple_ids_rejects():
    with pytest.raises(HTTPException) as exc:
        MustBeSelf(make_user("USER", id=1), [1, 2])
    assert exc.value.status_code == 403


# --- authorize_admin_or_self ---


@pytest.mark.asyncio
async def test_admin_or_self_admin_any_id():
    user = make_user("ADMIN", id=1)
    assert await authorize_admin_or_self(user, user_id=999) == user


@pytest.mark.asyncio
async def test_admin_or_self_user_own_id():
    user = make_user("USER", id=1)
    assert await authorize_admin_or_self(user, user_id=1) == user


@pytest.mark.asyncio
async def test_admin_or_self_user_other_id():
    with pytest.raises(HTTPException) as exc:
        await authorize_admin_or_self(make_user("USER", id=1), user_id=2)
    assert exc.value.status_code == 403


@pytest.mark.asyncio
async def test_admin_or_self_system_other_id_rejects():
    with pytest.raises(HTTPException) as exc:
        await authorize_admin_or_self(make_user("SYSTEM", id=1), user_id=2)
    assert exc.value.status_code == 403


# --- authorize_system_or_self ---


@pytest.mark.asyncio
async def test_system_or_self_admin_any_id():
    user = make_user("ADMIN", id=1)
    assert await authorize_system_or_self(user, user_id=999) == user


@pytest.mark.asyncio
async def test_system_or_self_system_any_id():
    user = make_user("SYSTEM", id=1)
    assert await authorize_system_or_self(user, user_id=999) == user


@pytest.mark.asyncio
async def test_system_or_self_user_own_id():
    user = make_user("USER", id=1)
    assert await authorize_system_or_self(user, user_id=1) == user


@pytest.mark.asyncio
async def test_system_or_self_user_other_id():
    with pytest.raises(HTTPException) as exc:
        await authorize_system_or_self(make_user("USER", id=1), user_id=2)
    assert exc.value.status_code == 403
