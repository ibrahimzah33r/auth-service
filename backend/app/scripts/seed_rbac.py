import asyncio

from sqlalchemy import select

from app.db.session import AsyncSessionLocal
from app.models.rbac import (
    Permission,
    Role,
    role_permissions,
)


ROLE_PERMISSIONS = {
    "user": {
        ("profile", "read"),
        ("profile", "write"),
    },
    "admin": {
        ("profile", "read"),
        ("profile", "write"),
        ("users", "read"),
        ("users", "write"),
        ("users", "delete"),
    },
}


async def get_or_create_role(
    db,
    role_name: str,
) -> Role:
    result = await db.execute(
        select(Role).where(
            Role.name == role_name
        )
    )

    role = result.scalar_one_or_none()

    if role is not None:
        return role

    role = Role(
        name=role_name,
    )

    db.add(role)
    await db.flush()

    return role


async def get_or_create_permission(
    db,
    resource: str,
    action: str,
) -> Permission:
    result = await db.execute(
        select(Permission).where(
            Permission.resource == resource,
            Permission.action == action,
        )
    )

    permission = result.scalar_one_or_none()

    if permission is not None:
        return permission

    permission = Permission(
        resource=resource,
        action=action,
    )

    db.add(permission)
    await db.flush()

    return permission


async def attach_permission(
    db,
    role: Role,
    permission: Permission,
) -> None:
    result = await db.execute(
        select(role_permissions).where(
            role_permissions.c.role_id == role.id,
            role_permissions.c.permission_id
            == permission.id,
        )
    )

    if result.first() is not None:
        return

    await db.execute(
        role_permissions.insert().values(
            role_id=role.id,
            permission_id=permission.id,
        )
    )


async def seed_rbac() -> None:
    async with AsyncSessionLocal() as db:
        for role_name, permissions in ROLE_PERMISSIONS.items():
            role = await get_or_create_role(
                db,
                role_name,
            )

            for resource, action in permissions:
                permission = await get_or_create_permission(
                    db,
                    resource,
                    action,
                )

                await attach_permission(
                    db,
                    role,
                    permission,
                )

        await db.commit()

    print("RBAC seed completed")


if __name__ == "__main__":
    asyncio.run(seed_rbac())