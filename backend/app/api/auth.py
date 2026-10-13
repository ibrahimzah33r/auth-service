from fastapi import (
    APIRouter,
    Cookie,
    Depends,
    HTTPException,
    Request,
    Response,
    status,
)
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.cookies import (
    clear_refresh_cookie,
    set_refresh_cookie,
)
from app.auth.dependencies import get_current_user
from app.auth.tokens import (
    create_access_token,
    create_refresh_token,
    get_refresh_token_expiry,
)
from app.config import settings
from app.db.session import get_db
from app.models.user import User
from app.schemas.user import (
    AccessTokenResponse,
    LogoutResponse,
    RefreshTokenRequest,
    TokenPairResponse,
    UserLogin,
    UserRegister,
    UserResponse,
)
from app.services.audit import write_audit_event
from app.services.authentication import authenticate_user
from app.services.rate_limit import (
    check_login_account_limit,
    check_login_ip_limit,
)
from app.services.refresh_tokens import (
    get_refresh_token,
    mark_refresh_token_used,
    refresh_token_is_expired,
    revoke_token_family,
    revoke_user_tokens,
    store_refresh_token,
)
from app.services.users import (
    create_user,
    get_user_by_email,
)


router = APIRouter(
    prefix="/auth",
    tags=["auth"],
)


def get_client_ip(request: Request) -> str:
    if request.client is None:
        return "unknown"

    return request.client.host


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
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    normalized_email = payload.email.lower()
    client_ip = get_client_ip(request)

    await check_login_ip_limit(
        client_ip
    )

    await check_login_account_limit(
        normalized_email
    )

    user = await authenticate_user(
        db=db,
        email=normalized_email,
        password=payload.password,
        client_ip=client_ip,
    )

    access_token = create_access_token(
        user.id
    )

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
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    normalized_email = payload.email.lower()
    client_ip = get_client_ip(request)

    await check_login_ip_limit(
        client_ip
    )

    await check_login_account_limit(
        normalized_email
    )

    user = await authenticate_user(
        db=db,
        email=normalized_email,
        password=payload.password,
        client_ip=client_ip,
    )

    access_token = create_access_token(
        user.id
    )

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
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = get_client_ip(request)

    stored_token = await get_refresh_token(
        db,
        payload.refresh_token,
    )

    if stored_token is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if refresh_token_is_expired(
        stored_token
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        )

    if stored_token.revoked:
        await revoke_token_family(
            db,
            stored_token.family_id,
        )

        await write_audit_event(
            db=db,
            event_type="refresh_token_reuse",
            outcome="denied",
            user_id=stored_token.user_id,
            client_ip=client_ip,
            detail="Revoked refresh token replayed",
        )

        await db.commit()

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

    await write_audit_event(
        db=db,
        event_type="token_refresh",
        outcome="success",
        user_id=stored_token.user_id,
        client_ip=client_ip,
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
    request: Request,
    response: Response,
    refresh_token: str | None = Cookie(
        default=None,
        alias=settings.refresh_cookie_name,
    ),
    db: AsyncSession = Depends(get_db),
):
    client_ip = get_client_ip(request)

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
        clear_refresh_cookie(
            response
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token",
        )

    if refresh_token_is_expired(
        stored_token
    ):
        clear_refresh_cookie(
            response
        )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token expired",
        )

    if stored_token.revoked:
        await revoke_token_family(
            db,
            stored_token.family_id,
        )

        await write_audit_event(
            db=db,
            event_type="refresh_token_reuse",
            outcome="denied",
            user_id=stored_token.user_id,
            client_ip=client_ip,
            detail="Revoked refresh token replayed",
        )

        await db.commit()

        clear_refresh_cookie(
            response
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

    set_refresh_cookie(
        response,
        new_refresh_token,
    )

    await write_audit_event(
        db=db,
        event_type="token_refresh",
        outcome="success",
        user_id=stored_token.user_id,
        client_ip=client_ip,
    )

    await db.commit()

    return AccessTokenResponse(
        access_token=access_token,
    )


@router.post(
    "/logout",
    response_model=LogoutResponse,
)
async def logout(
    payload: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = get_client_ip(request)

    stored_token = await get_refresh_token(
        db,
        payload.refresh_token,
    )

    if stored_token is not None:
        await revoke_token_family(
            db,
            stored_token.family_id,
        )

        await write_audit_event(
            db=db,
            event_type="logout",
            outcome="success",
            user_id=stored_token.user_id,
            client_ip=client_ip,
        )

        await db.commit()

    return LogoutResponse(
        message="Logged out",
    )


@router.post(
    "/logout/browser",
    response_model=LogoutResponse,
)
async def browser_logout(
    request: Request,
    response: Response,
    refresh_token: str | None = Cookie(
        default=None,
        alias=settings.refresh_cookie_name,
    ),
    db: AsyncSession = Depends(get_db),
):
    client_ip = get_client_ip(request)

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

            await write_audit_event(
                db=db,
                event_type="logout",
                outcome="success",
                user_id=stored_token.user_id,
                client_ip=client_ip,
            )

            await db.commit()

    clear_refresh_cookie(
        response
    )

    return LogoutResponse(
        message="Logged out",
    )


@router.post(
    "/logout-all",
    response_model=LogoutResponse,
)
async def logout_all(
    payload: RefreshTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    client_ip = get_client_ip(request)

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

    await write_audit_event(
        db=db,
        event_type="logout_all",
        outcome="success",
        user_id=stored_token.user_id,
        client_ip=client_ip,
    )

    await db.commit()

    return LogoutResponse(
        message="Logged out from all sessions",
    )


@router.get(
    "/me",
    response_model=UserResponse,
)
async def me(
    current_user: User = Depends(
        get_current_user
    ),
):
    return current_user