from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from passlib.context import CryptContext
from authlib.integrations.starlette_client import OAuth
from fastapi import HTTPException, Request, Depends

from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth = OAuth()
oauth.register(
    name=settings.OAUTH_PROVIDER,
    client_id=settings.OAUTH_CLIENT_ID,
    client_secret=settings.OAUTH_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth"
    if settings.OAUTH_PROVIDER == "google"
    else "https://github.com/login/oauth/authorize",
    access_token_url="https://oauth2.googleapis.com/token"
    if settings.OAUTH_PROVIDER == "google"
    else "https://github.com/login/oauth/access_token",
    client_kwargs={"scope": "openid email profile"},
)

ALGORITHM = "HS256"


def create_access_token(subject: str | Any, expires_delta: timedelta) -> str:
    """Issue a JWT token after OAuth authentication."""
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode = {"exp": expire, "sub": str(subject)}
    return jwt.encode(to_encode, settings.SECRET_KEY, algorithm=ALGORITHM)


async def get_oauth_user(request: Request) -> Dict[str, Any]:
    """Retrieve authenticated user from OAuth session."""
    token = await oauth.google.authorize_access_token(request)
    user = await oauth.google.parse_id_token(request, token)
    if not user:
        raise HTTPException(status_code=403, detail="OAuth authentication failed")
    return user


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
