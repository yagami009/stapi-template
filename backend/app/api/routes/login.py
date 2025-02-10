from datetime import timedelta
from typing import Annotated, Any

import httpx
from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from app import crud
from app.api.deps import CurrentUser, SessionDep
from app.core import security
from app.core.config import settings
from app.models import Message, NewPassword, Token, UserPublic
from app.utils import generate_password_reset_token, generate_reset_password_email, send_email, verify_password_reset_token

router = APIRouter(tags=["login"])

# ------------------------
# Standard JWT Login (unchanged)
# ------------------------
@router.post("/login/access-token")
def login_access_token(
    session: SessionDep, form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
) -> Token:
    user = crud.authenticate(
        session=session, email=form_data.username, password=form_data.password
    )
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect email or password")
    elif not user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(
        access_token=security.create_access_token(
            user.id, expires_delta=access_token_expires
        )
    )

# ------------------------
# OAuth Login (New)
# ------------------------
@router.post("/login/oauth")
async def login_oauth(session: SessionDep, provider: str, token: str) -> Token:
    """
    Login via OAuth provider (Google, GitHub, etc.)
    """
    if provider not in ["google", "github"]:
        raise HTTPException(status_code=400, detail="Unsupported OAuth provider")

    # Get user data from OAuth provider
    user_data = await get_oauth_user_info(provider, token)

    if not user_data:
        raise HTTPException(status_code=400, detail="Invalid OAuth token")

    # Extract relevant user info
    email = user_data.get("email")
    name = user_data.get("name")

    if not email:
        raise HTTPException(status_code=400, detail="OAuth provider did not return an email")

    # Check if user exists, otherwise create new user
    user = crud.get_user_by_email(session, email=email)
    if not user:
        user = crud.create_user(session, email=email, full_name=name, oauth_provider=provider)

    # Generate JWT token for session
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    return Token(
        access_token=security.create_access_token(
            user.id, expires_delta=access_token_expires
        )
    )

# ------------------------
# Function to Fetch OAuth User Data
# ------------------------
async def get_oauth_user_info(provider: str, token: str) -> dict | None:
    """
    Fetch user info from OAuth provider using the access token.
    """
    provider_endpoints = {
        "google": "https://www.googleapis.com/oauth2/v2/userinfo",
        "github": "https://api.github.com/user"
    }

    url = provider_endpoints.get(provider)
    if not url:
        return None

    async with httpx.AsyncClient() as client:
        headers = {"Authorization": f"Bearer {token}"}
        response = await client.get(url, headers=headers)

    if response.status_code != 200:
        return None
    
    return response.json()
