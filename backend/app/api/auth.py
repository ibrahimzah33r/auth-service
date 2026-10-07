from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.passwords import verify_password
from app.auth.tokens import (
    create_access_token,
    create_refresh_token,
    get_refresh_token_expiry,
)
from app.db.session import get_db
from app.schemas.user import (
    RefreshTokenRequest,
    TokenPairResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.services.refresh_tokens import (
    get_refresh_token,
    mark_refresh_token_used,
    refresh_token_is_expired,
    revoke_token_family,
    store_refresh_token,
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
    response_model=TokenPairResponse,
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
    refresh_token = create_refresh_token()

    await store_refresh_token(
        db=db,
        user_id=user.id,
        token=refresh_token,
        expires_at=get_refresh_token_expiry(),
    )

    return TokenPairResponse(
        access_token=access_token,
        refresh_token=refresh_token,
    )


@router.post(
    "/refresh",
    response_model=TokenPairResponse,
)
async def refresh(
    payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    stored_token = await get_refresh_token(
        db,
        payload.refresh_token,
    )

    if stored_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if refresh_token_is_expired(stored_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        )

    if stored_token.revoked:
        await revoke_token_family(
            db,
            stored_token.family_id,
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token reuse detected",
        )

    await mark_refresh_token_used(
        db,
        stored_token,
    )

    new_refresh_token = create_refresh_token()

    await store_refresh_token(
        db=db,
        user_id=stored_token.user_id,
        token=new_refresh_token,
        expires_at=get_refresh_token_expiry(),
        family_id=stored_token.family_id,
    )

    access_token = create_access_token(
        stored_token.user_id
    )

    await db.commit()

    return TokenPairResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
    )