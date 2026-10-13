import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class AuditEventResponse(BaseModel):
    model_config = ConfigDict(
        from_attributes=True
    )

    id: uuid.UUID
    user_id: uuid.UUID | None
    event_type: str
    outcome: str
    client_ip: str | None
    detail: str | None
    created_at: datetime