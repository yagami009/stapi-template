import uuid
from typing import Any
from sqlmodel import Session, select

from app.core.security import get_password_hash, verify_password
from app.models import Item, ItemCreate, User, UserCreate, UserUpdate


def create_user(*, session: Session, user_create: UserCreate) -> User:
    """
    Creates a new user for standard email/password signups.
    """
    if not user_create.password:
        raise ValueError("Password is required for standard signup users.")

    db_obj = User.model_validate(
        user_create, update={"hashed_password": get_password_hash(user_create.password)}
    )
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    return db_obj


def create_oauth_user(
    *, session: Session, email: str, full_name: str, oauth_provider: str, oauth_id: str
) -> User:
    """
    Creates a new user for OAuth-based authentication.
    """
    db_obj = User(
        email=email,
        full_name=full_name,
        oauth_provider=oauth_provider,
        oauth_id=oauth_id,
        is_active=True,
    )
    session.add(db_obj)
    session.commit()
    session.refresh(db_obj)
    return db_obj


def update_user(*, session: Session, db_user: User, user_in: UserUpdate) -> Any:
    """
    Updates a user account.
    """
    user_data = user_in.model_dump(exclude_unset=True)
    extra_data = {}

    if "password" in user_data:
        password = user_data["password"]
        hashed_password = get_password_hash(password)
        extra_data["hashed_password"] = hashed_password

    db_user.sqlmodel_update(user_data, update=extra_data)
    session.add(db_user)
    session.commit()
    session.refresh(db_user)
    return db_user


def get_user_by_email(*, session: Session, email: str) -> User | None:
    """
    Fetches a user by email.
    """
    statement = select(User).where(User.email == email)
    return session.exec(statement).first()


def get_user_by_oauth(*, session: Session, oauth_provider: str, oauth_id: str) -> User | None:
    """
    Fetches a user by their OAuth provider and OAuth ID.
    """
    statement = select(User).where(
        (User.oauth_provider == oauth_provider) & (User.oauth_id == oauth_id)
    )
    return session.exec(statement).first()


def authenticate(*, session: Session, email: str, password: str) -> User | None:
    """
    Authenticates a user using email/password login.
    """
    db_user = get_user_by_email(session=session, email=email)
    if not db_user or not db_user.hashed_password:
        return None  # OAuth users don’t have passwords
    if not verify_password(password, db_user.hashed_password):
        return None
    return db_user


def create_item(*, session: Session, item_in: ItemCreate, owner_id: uuid.UUID) -> Item:
    """
    Creates an item owned by a user.
    """
    db_item = Item.model_validate(item_in, update={"owner_id": owner_id})
    session.add(db_item)
    session.commit()
    session.refresh(db_item)
    return db_item
