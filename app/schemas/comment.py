import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class CommentCreate(BaseModel):
    body: str = Field(min_length=1)


class CommentResponse(BaseModel):
    id: uuid.UUID
    vuln_id: uuid.UUID
    user_id: uuid.UUID
    username: str
    body: str
    created_at: datetime

    model_config = {"from_attributes": True}
