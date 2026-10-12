from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.passwords import verify_password
from app.models.user import User
from app.services.rate_limit import (
    clear_login_failures,
    record_login_failure,
)
from app.services.users import get_user_by_email


async def authenticate_user(
    db: AsyncSession,
    email: str,
    password: str,
) -> User:
    user = await get_user_by_email(
        db,
        email,
    )

    if user is None:
        await record_login_failure(email)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not verify_password(
        password,
        user.password_hash,
    ):
        await record_login_failure(email)

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    await clear_login_failures(email)

    return user