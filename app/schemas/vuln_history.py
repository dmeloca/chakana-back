import uuid
from datetime import datetime

from pydantic import BaseModel


class VulnHistoryEntry(BaseModel):
    id: uuid.UUID
    vuln_id: uuid.UUID
    user_id: uuid.UUID | None
    username: str | None
    changes: dict
    changed_at: datetime

    model_config = {"from_attributes": True}
