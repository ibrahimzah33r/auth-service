from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.passwords import hash_password
from app.models.user import User
from app.services.rbac import assign_role_to_user


async def get_user_by_email(
    db: AsyncSession,
    email: str,
) -> User | None:
    result = await db.execute(
        select(User).where(User.email == email)
    )

    return result.scalar_one_or_none()


async def create_user(
    db: AsyncSession,
    email: str,
    password: str,
) -> User:
    user = User(
        email=email,
        password_hash=hash_password(password),
    )

    db.add(user)

    await db.flush()

    await assign_role_to_user(
        db=db,
        user_id=user.id,
        role_name="user",
    )

    await db.commit()
    await db.refresh(user)

    return user