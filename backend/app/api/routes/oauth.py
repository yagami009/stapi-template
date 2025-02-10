from fastapi import APIRouter, Depends, HTTPException
from authlib.integrations.starlette_client import OAuth
from starlette.requests import Request
from starlette.responses import RedirectResponse
from sqlalchemy.orm import Session
from app.core.config import settings
from app.api.deps import get_db
from app import crud
from app.models import User, UserCreate
from app.core.security import create_access_token
from datetime import timedelta

router = APIRouter(tags=["oauth"])

oauth = OAuth()

# OAuth Providers Configuration
oauth.register(
    "google",
    client_id=settings.GOOGLE_CLIENT_ID,
    client_secret=settings.GOOGLE_CLIENT_SECRET,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    access_token_url="https://oauth2.googleapis.com/token",
    client_kwargs={"scope": "openid email profile"},
)

oauth.register(
    "github",
    client_id=settings.GITHUB_CLIENT_ID,
    client_secret=settings.GITHUB_CLIENT_SECRET,
    authorize_url="https://github.com/login/oauth/authorize",
    access_token_url="https://github.com/login/oauth/access_token",
    client_kwargs={"scope": "user:email"},
)

oauth.register(
    "linkedin",
    client_id=settings.LINKEDIN_CLIENT_ID,
    client_secret=settings.LINKEDIN_CLIENT_SECRET,
    authorize_url="https://www.linkedin.com/oauth/v2/authorization",
    access_token_url="https://www.linkedin.com/oauth/v2/accessToken",
    client_kwargs={"scope": "r_liteprofile r_emailaddress"},
)

# Redirect to OAuth Provider
@router.get("/login/{provider}")
async def oauth_login(provider: str, request: Request):
    if provider not in oauth.registry:
        raise HTTPException(status_code=400, detail="Unsupported OAuth provider")
    redirect_uri = str(request.url_for("oauth_callback", provider=provider))
    return await oauth.create_client(provider).authorize_redirect(request, redirect_uri)

# OAuth Callback Handler
@router.get("/auth/callback/{provider}")
async def oauth_callback(provider: str, request: Request, db: Session = Depends(get_db)):
    if provider not in oauth.registry:
        raise HTTPException(status_code=400, detail="Unsupported OAuth provider")
    
    client = oauth.create_client(provider)
    token = await client.authorize_access_token(request)
    user_data = await client.parse_id_token(request, token) if provider == "google" else await client.get("userinfo", token=token)
    
    if provider == "github":
        user_email_resp = await client.get("user/emails", token=token)
        user_data = user_email_resp.json()[0] if user_email_resp else None
    
    if provider == "linkedin":
        email_resp = await client.get("https://api.linkedin.com/v2/emailAddress?q=members&projection=(elements*(handle~))", token=token)
        profile_resp = await client.get("https://api.linkedin.com/v2/me", token=token)
        user_data = {
            "email": email_resp.json()["elements"][0]["handle~"]["emailAddress"],
            "name": profile_resp.json().get("localizedFirstName", "") + " " + profile_resp.json().get("localizedLastName", ""),
        }
    
    if not user_data:
        raise HTTPException(status_code=400, detail="Failed to retrieve user info")

    email = user_data.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Email not provided by OAuth provider")

    user = crud.get_user_by_email(session=db, email=email)
    if not user:
        new_user = UserCreate(email=email, password="", full_name=user_data.get("name", ""))
        user = crud.create_user(session=db, user_create=new_user)
    
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(user.id, expires_delta=access_token_expires)
    
    return RedirectResponse(url=f"{settings.FRONTEND_HOST}/oauth-success?token={access_token}")
