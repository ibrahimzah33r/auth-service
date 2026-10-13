from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.passwords import verify_password
from app.models.user import User
from app.services.audit import write_audit_event
from app.services.rate_limit import (
    clear_login_failures,
    record_login_failure,
)
from app.services.users import get_user_by_email


async def authenticate_user(
    db: AsyncSession,
    email: str,
    password: str,
    client_ip: str | None = None,
) -> User:
    user = await get_user_by_email(
        db,
        email,
    )

    if user is None:
        await record_login_failure(email)

        await write_audit_event(
            db=db,
            event_type="login",
            outcome="failure",
            client_ip=client_ip,
            detail="Invalid credentials",
        )

        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not verify_password(
        password,
        user.password_hash,
    ):
        await record_login_failure(email)

        await write_audit_event(
            db=db,
            event_type="login",
            outcome="failure",
            user_id=user.id,
            client_ip=client_ip,
            detail="Invalid credentials",
        )

        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password",
        )

    if not user.is_active:
        await write_audit_event(
            db=db,
            event_type="login",
            outcome="denied",
            user_id=user.id,
            client_ip=client_ip,
            detail="Inactive account",
        )

        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
        )

    await clear_login_failures(email)

    await write_audit_event(
        db=db,
        event_type="login",
        outcome="success",
        user_id=user.id,
        client_ip=client_ip,
    )

    return user