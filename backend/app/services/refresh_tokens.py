from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.tokens import hash_refresh_token
from app.models.refresh_token import RefreshToken


async def store_refresh_token(
    db: AsyncSession,
    user_id: UUID,
    token: str,
    expires_at: datetime,
) -> RefreshToken:
    refresh_token = RefreshToken(
        user_id=user_id,
        token_hash=hash_refresh_token(token),
        expires_at=expires_at,
    )

    db.add(refresh_token)

    await db.commit()
    await db.refresh(refresh_token)

    return refresh_token


async def get_valid_refresh_token(
    db: AsyncSession,
    token: str,
) -> RefreshToken | None:
    token_hash = hash_refresh_token(token)

    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash
        )
    )

    refresh_token = result.scalar_one_or_none()

    if refresh_token is None:
        return None

    if refresh_token.expires_at <= datetime.now(timezone.utc):
        return None

    return refresh_token