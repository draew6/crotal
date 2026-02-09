from fastapi import Depends, HTTPException
from typing import Annotated
from .models import UserInfo
from .authentication import User


async def authorize_admin(user: User) -> UserInfo:
    if user and user.role == "ADMIN":
        return user
    raise HTTPException(status_code=403)


async def authorize_system(user: User) -> UserInfo:
    if user and user.role in ["ADMIN", "SYSTEM"]:
        return user
    raise HTTPException(status_code=403)


System = Annotated[UserInfo, Depends(authorize_system)]
Admin = Annotated[UserInfo, Depends(authorize_admin)]


def MustBeSelf(user: UserInfo, user_ids: list[int]) -> None:
    if user.role in ["ADMIN", "SYSTEM"]:
        return
    if [user.id] == user_ids:
        return
    raise HTTPException(status_code=403, detail="Forbidden")


async def authorize_admin_or_self(user: User, user_id: int) -> UserInfo:
    if user_id != user.id and user.role != "ADMIN":
        raise HTTPException(status_code=403)
    return user


async def authorize_system_or_self(user: User, user_id: int) -> UserInfo:
    if user_id != user.id and user.role not in ["ADMIN", "SYSTEM"]:
        raise HTTPException(status_code=403)
    return user


AdminOrSelf = Annotated[UserInfo, Depends(authorize_admin_or_self)]
SystemOrSelf = Annotated[UserInfo, Depends(authorize_system_or_self)]
