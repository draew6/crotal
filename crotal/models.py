from pydantic import BaseModel
from datetime import datetime
from typing import Literal


class AuthTokens(BaseModel):
    access_token: str
    refresh_token: str


class UserInfo(BaseModel):
    id: int
    name: str
    role: Literal["USER", "SYSTEM", "ADMIN"]
    exp: datetime | None = None
