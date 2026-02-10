from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    auth_login_url: str
    jwt_secret: str
    cookie_secret: str
    root_domain: str


@lru_cache
def get_settings() -> Settings:
    return Settings()
