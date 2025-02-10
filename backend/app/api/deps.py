from collections.abc import Generator
from typing import Annotated

import jwt
import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jwt.exceptions import InvalidTokenError
from pydantic import ValidationError
from sqlmodel import Session

from app.core import security
from app.core.config import settings
from app.core.db import engine
from app.models import TokenPayload, User
from app import crud

# OAuth2 Bearer Token Scheme for JWT & OAuth
reusable_oauth2 = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/login/access-token"
)

# Function to get DB session
def get_db() -> Generator[Session, None, None]:
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_db)]
TokenDep = Annotated[str, Depends(reusable_oauth2)]

OAUTH_PROVIDERS = {
    "google": {
        "user_info_url": "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    "github": {
        "user_info_url": "https://api.github.com/user",
    },
    "linkedin": {
        "user_info_url": "https://api.linkedin.com/v2/me",
        "email_url": "https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))",
    },
}


async def validate_oauth_token(provider: str, token: str) -> dict | None:
    """
    Validates an OAuth token against the provider's API (Google, GitHub, LinkedIn).
    Returns user data if valid, raises HTTPException otherwise.
    """
    if provider not in OAUTH_PROVIDERS:
        raise HTTPException(status_code=400, detail="Unsupported OAuth provider")

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {token}"}
        user_info_url = OAUTH_PROVIDERS[provider]["user_info_url"]
        response = await client.get(user_info_url, headers=headers)

        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid OAuth token")

        user_data = response.json()

        # LinkedIn requires a separate request for email
        if provider == "linkedin":
            email_response = await client.get(OAUTH_PROVIDERS["linkedin"]["email_url"], headers=headers)
            if email_response.status_code == 200:
                email_data = email_response.json()
                elements = email_data.get("elements", [])
                if elements:
                    user_data["email"] = elements[0]["handle~"]["emailAddress"]

        return user_data


def get_current_user(session: SessionDep, token: TokenDep) -> User:
    """
    Fetches the current user from JWT token.
    """
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[security.ALGORITHM]
        )
        token_data = TokenPayload(**payload)
    except (InvalidTokenError, ValidationError):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Could not validate credentials",
        )

    user = session.get(User, token_data.sub)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return user


async def get_current_oauth_user(
    provider: str, token: str, session: SessionDep
) -> User:
    """
    Validates OAuth token, fetches user info, and creates user if not exists.
    """
    user_info = await validate_oauth_token(provider, token)
    if not user_info:
        raise HTTPException(status_code=401, detail="OAuth token invalid or expired")

    email = user_info.get("email")
    full_name = user_info.get("name") or user_info.get("login")  # GitHub uses "login"

    if not email:
        raise HTTPException(status_code=400, detail="OAuth provider did not return an email")

    user = crud.get_user_by_email(session=session, email=email)
    if not user:
        user = crud.create_oauth_user(
            session=session,
            email=email,
            full_name=full_name or "",
            oauth_provider=provider,
            oauth_id=user_info.get("id"),
        )

    return user


CurrentUser = Annotated[User, Depends(get_current_user)]


def get_current_active_superuser(current_user: CurrentUser) -> User:
    """
    Ensures the current user is a superuser.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=403, detail="The user doesn't have enough privileges"
        )
    return current_user
