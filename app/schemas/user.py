import uuid
from datetime import datetime

from pydantic import BaseModel, Field


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserCreate(BaseModel):
    username: str = Field(min_length=3, max_length=50, pattern=r'^[a-zA-Z0-9_.-]+$')
    password: str = Field(min_length=8)
    role: str = Field(default='developer', pattern=r'^(admin|manager|pentester|developer|viewer|reviewer)$')


class UserPasswordChange(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)
