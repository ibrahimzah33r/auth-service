from fastapi import APIRouter, Cookie, Depends, HTTPException, Response, status
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
    LogoutResponse,
    RefreshTokenRequest,
    TokenPairResponse,
    UserLogin,
    UserRegister,
    UserResponse,
    AccessTokenResponse,
)
from app.services.refresh_tokens import (
    get_refresh_token,
    mark_refresh_token_used,
    refresh_token_is_expired,
    revoke_token_family,
    revoke_user_tokens,
    store_refresh_token,
)
from app.services.users import create_user, get_user_by_email
from app.auth.dependencies import get_current_user
from app.models.user import User
from app.auth.cookies import (
    clear_refresh_cookie,
    set_refresh_cookie,
)
from app.config import settings

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
    "/login/browser",
    response_model=AccessTokenResponse,
)
async def browser_login(
    payload: UserLogin,
    response: Response,
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

    set_refresh_cookie(
        response,
        refresh_token,
    )

    return AccessTokenResponse(
        access_token=access_token,
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

@router.post(
    "/refresh/browser",
    response_model=AccessTokenResponse,
)
async def browser_refresh(
    response: Response,
    refresh_token: str | None = Cookie(
        default=None,
        alias=settings.refresh_cookie_name,
    ),
    db: AsyncSession = Depends(get_db),
):
    if refresh_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token missing",
        )

    stored_token = await get_refresh_token(
        db,
        refresh_token,
    )

    if stored_token is None:
        clear_refresh_cookie(response)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if refresh_token_is_expired(stored_token):
        clear_refresh_cookie(response)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        )

    if stored_token.revoked:
        await revoke_token_family(
            db,
            stored_token.family_id,
        )

        clear_refresh_cookie(response)

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

    set_refresh_cookie(
        response,
        new_refresh_token,
    )

    return AccessTokenResponse(
        access_token=access_token,
    )

@router.post(
    "/logout",
    response_model=LogoutResponse,
)
async def logout(
    payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    stored_token = await get_refresh_token(
        db,
        payload.refresh_token,
    )

    if stored_token is not None:
        await revoke_token_family(
            db,
            stored_token.family_id,
        )

    return LogoutResponse(
        message="Logged out",
    )

@router.post(
    "/logout/browser",
    response_model=LogoutResponse,
)
async def browser_logout(
    response: Response,
    refresh_token: str | None = Cookie(
        default=None,
        alias=settings.refresh_cookie_name,
    ),
    db: AsyncSession = Depends(get_db),
):
    if refresh_token is not None:
        stored_token = await get_refresh_token(
            db,
            refresh_token,
        )

        if stored_token is not None:
            await revoke_token_family(
                db,
                stored_token.family_id,
            )

    clear_refresh_cookie(response)

    return LogoutResponse(
        message="Logged out",
    )

@router.post(
    "/logout-all",
    response_model=LogoutResponse,
)
async def logout_all(
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

    await revoke_user_tokens(
        db,
        stored_token.user_id,
    )

    return LogoutResponse(
        message="Logged out from all sessions",
    )

@router.get(
    "/me",
    response_model=UserResponse,
)
async def me(
    current_user: User = Depends(get_current_user),
):
    return current_user