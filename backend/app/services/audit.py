from uuid import UUID

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit import AuditEvent


async def write_audit_event(
    db: AsyncSession,
    event_type: str,
    outcome: str,
    user_id: UUID | None = None,
    client_ip: str | None = None,
    detail: str | None = None,
) -> AuditEvent:
    event = AuditEvent(
        user_id=user_id,
        event_type=event_type,
        outcome=outcome,
        client_ip=client_ip,
        detail=detail,
    )

    db.add(event)

    await db.flush()

    return event


async def get_recent_audit_events(
    db: AsyncSession,
    limit: int = 100,
) -> list[AuditEvent]:
    result = await db.execute(
        select(AuditEvent)
        .order_by(
            desc(AuditEvent.created_at)
        )
        .limit(limit)
    )

    return list(
        result.scalars().all()
    )