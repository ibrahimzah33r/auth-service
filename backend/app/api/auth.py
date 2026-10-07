from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.passwords import verify_password
from app.auth.tokens import create_access_token
from app.db.session import get_db
from app.schemas.user import (
    AccessTokenResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.services.users import create_user, get_user_by_email


router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    payload: UserRegister,
    db: AsyncSession = Depends(get_db),
):
    normalized_email = payload.email.lower()

    existing_user = await get_user_by_email(
        db,
        normalized_email,
    )

    if existing_user is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    try:
        user = await create_user(
            db,
            email=normalized_email,
            password=payload.password,
        )

    except IntegrityError:
        await db.rollback()

        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    return user


@router.post(
    "/login",
    response_model=AccessTokenResponse,
)
async def login(
    payload: UserLogin,
    db: AsyncSession = Depends(get_db),
):
    normalized_email = payload.email.lower()

    user = await get_user_by_email(
        db,
        normalized_email,
    )

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not verify_password(
        payload.password,
        user.password_hash,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    access_token = create_access_token(user.id)

    return AccessTokenResponse(
        access_token=access_token,
    )