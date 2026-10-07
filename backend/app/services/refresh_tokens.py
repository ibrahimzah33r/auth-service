import uuid
from datetime import datetime, timezone
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.tokens import hash_refresh_token
from app.models.refresh_token import RefreshToken


async def store_refresh_token(
    db: AsyncSession,
    user_id: UUID,
    token: str,
    expires_at: datetime,
    family_id: UUID | None = None,
) -> RefreshToken:
    refresh_token = RefreshToken(
        user_id=user_id,
        family_id=family_id or uuid.uuid4(),
        token_hash=hash_refresh_token(token),
        expires_at=expires_at,
    )

    db.add(refresh_token)

    await db.commit()
    await db.refresh(refresh_token)

    return refresh_token


async def get_refresh_token(
    db: AsyncSession,
    token: str,
) -> RefreshToken | None:
    token_hash = hash_refresh_token(token)

    result = await db.execute(
        select(RefreshToken).where(
            RefreshToken.token_hash == token_hash
        )
    )

    return result.scalar_one_or_none()


def refresh_token_is_expired(
    refresh_token: RefreshToken,
) -> bool:
    return refresh_token.expires_at <= datetime.now(timezone.utc)


async def mark_refresh_token_used(
    db: AsyncSession,
    refresh_token: RefreshToken,
) -> None:
    refresh_token.revoked = True
    refresh_token.used_at = datetime.now(timezone.utc)

    await db.flush()


async def revoke_token_family(
    db: AsyncSession,
    family_id: UUID,
) -> None:
    await db.execute(
        update(RefreshToken)
        .where(
            RefreshToken.family_id == family_id,
            RefreshToken.revoked.is_(False),
        )
        .values(revoked=True)
    )

    await db.commit()