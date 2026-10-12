from uuid import UUID

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rbac import (
    Permission,
    Role,
    role_permissions,
    user_roles,
)


async def get_role_by_name(
    db: AsyncSession,
    role_name: str,
) -> Role | None:
    result = await db.execute(
        select(Role).where(Role.name == role_name)
    )

    return result.scalar_one_or_none()


async def assign_role_to_user(
    db: AsyncSession,
    user_id: UUID,
    role_name: str,
) -> None:
    role = await get_role_by_name(
        db,
        role_name,
    )

    if role is None:
        raise ValueError(
            f"Role '{role_name}' does not exist"
        )

    existing = await db.execute(
        select(user_roles).where(
            user_roles.c.user_id == user_id,
            user_roles.c.role_id == role.id,
        )
    )

    if existing.first() is not None:
        return

    await db.execute(
        insert(user_roles).values(
            user_id=user_id,
            role_id=role.id,
        )
    )


async def get_user_roles(
    db: AsyncSession,
    user_id: UUID,
) -> list[str]:
    result = await db.execute(
        select(Role.name)
        .join(
            user_roles,
            Role.id == user_roles.c.role_id,
        )
        .where(
            user_roles.c.user_id == user_id
        )
    )

    return list(result.scalars().all())


async def get_user_permissions(
    db: AsyncSession,
    user_id: UUID,
) -> set[str]:
    result = await db.execute(
        select(
            Permission.resource,
            Permission.action,
        )
        .join(
            role_permissions,
            Permission.id
            == role_permissions.c.permission_id,
        )
        .join(
            Role,
            Role.id == role_permissions.c.role_id,
        )
        .join(
            user_roles,
            Role.id == user_roles.c.role_id,
        )
        .where(
            user_roles.c.user_id == user_id
        )
    )

    return {
        f"{resource}:{action}"
        for resource, action in result.all()
    }