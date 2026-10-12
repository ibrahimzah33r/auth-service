from fastapi import APIRouter, Depends

from app.auth.dependencies import (
    get_current_user,
    require_permission,
)
from app.models.user import User


router = APIRouter(
    prefix="/protected",
    tags=["protected"],
)


@router.get("/authenticated")
async def authenticated_only(
    current_user: User = Depends(get_current_user),
):
    return {
        "message": "You are authenticated",
        "user_id": str(current_user.id),
    }


@router.get("/profile")
async def read_profile(
    current_user: User = Depends(
        require_permission("profile:read")
    ),
):
    return {
        "message": "You can read profiles",
        "user_id": str(current_user.id),
    }


@router.get("/users")
async def read_users(
    current_user: User = Depends(
        require_permission("users:read")
    ),
):
    return {
        "message": "You can read users",
        "user_id": str(current_user.id),
    }


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: str,
    current_user: User = Depends(
        require_permission("users:delete")
    ),
):
    return {
        "message": f"Authorized to delete user {user_id}",
        "authorized_by": str(current_user.id),
    }