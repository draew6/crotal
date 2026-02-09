from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from pydantic import BaseModel, ValidationError
from typing import Annotated
from jose import jwt, ExpiredSignatureError
from itsdangerous import BadSignature, Signer
from .config import get_settings
from .models import AuthTokens, UserInfo

access_token_scheme = OAuth2PasswordBearer(tokenUrl=get_settings().auth_login_url, auto_error=False)

BearerAccessToken = Annotated[str | None, Depends(access_token_scheme)]


def ExtractFromCookies[T: BaseModel](model: type[T]):
    def dependency(request: Request) -> T | None:
        try:
            data = {field: request.cookies.get(field) for field in model.model_fields}
            return model(**data)
        except ValidationError as e:
            print(e.errors())
            return None

    return dependency


UnverifiedAuthTokens = Annotated[
    AuthTokens | None, Depends(ExtractFromCookies(AuthTokens))
]


def get_verified_auth_tokens(
    unverified_auth_tokens: UnverifiedAuthTokens,
) -> AuthTokens | None:
    if not unverified_auth_tokens:
        return None
    signer = Signer(get_settings().cookie_secret)
    try:
        verified_refresh_token = signer.unsign(unverified_auth_tokens.refresh_token)
        verified_access_token = signer.unsign(unverified_auth_tokens.access_token)
    except BadSignature:
        return None
    return AuthTokens(
        access_token=verified_access_token.decode(),
        refresh_token=verified_refresh_token.decode(),
    )


VerifiedAuthTokens = Annotated[AuthTokens | None, Depends(get_verified_auth_tokens)]


async def get_user_info(
    header_access_token: BearerAccessToken,
    cookie_auth_tokens: VerifiedAuthTokens,
) -> UserInfo | None:
    if not header_access_token and not cookie_auth_tokens:
        return None
    if header_access_token:
        try:
            payload = jwt.decode(header_access_token, get_settings().jwt_secret, algorithms=["HS256"])
            return UserInfo(**payload)
        except ExpiredSignatureError:
            pass
    if cookie_auth_tokens:
        try:
            payload = jwt.decode(
                cookie_auth_tokens.access_token, get_settings().jwt_secret, algorithms=["HS256"]
            )
            return UserInfo(**payload)
        except ExpiredSignatureError:
            pass
    return None


OptionalUser = Annotated[UserInfo | None, Depends(get_user_info)]


async def authenticate(
    user_info: OptionalUser,
) -> UserInfo:
    if not user_info:
        raise HTTPException(status_code=401)
    return user_info


User = Annotated[UserInfo, Depends(authenticate)]
