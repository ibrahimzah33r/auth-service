from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_permission
from app.db.session import get_db
from app.models.user import User
from app.schemas.audit import AuditEventResponse
from app.services.audit import get_recent_audit_events


router = APIRouter(
    prefix="/audit",
    tags=["audit"],
)


@router.get(
    "/events",
    response_model=list[AuditEventResponse],
)
async def list_audit_events(
    limit: int = Query(
        default=100,
        ge=1,
        le=500,
    ),
    current_user: User = Depends(
        require_permission("audit:read")
    ),
    db: AsyncSession = Depends(get_db),
):
    return await get_recent_audit_events(
        db=db,
        limit=limit,
    )