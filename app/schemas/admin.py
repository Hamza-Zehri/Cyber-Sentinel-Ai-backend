from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field


class UserOut(BaseModel):
    id: str
    full_name: str
    email: EmailStr
    role: str
    is_active: bool
    is_verified: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class UserUpdate(BaseModel):
    full_name: Optional[str] = Field(None, min_length=2, max_length=120)
    is_active: Optional[bool] = None
    role_name: Optional[str] = None


class RoleOut(BaseModel):
    id: str
    name: str
    description: Optional[str]
    permission_codes: list[str] = []

    model_config = {"from_attributes": True}


class RoleCreate(BaseModel):
    name: str = Field(min_length=2, max_length=50)
    description: Optional[str] = Field(None, max_length=255)
    permission_codes: list[str] = []


class RoleUpdate(BaseModel):
    description: Optional[str] = Field(None, max_length=255)
    permission_codes: Optional[list[str]] = None


class AuditLogOut(BaseModel):
    id: str
    user_id: Optional[str]
    action: str
    module: str
    ip_address: Optional[str]
    result: str
    details: Optional[str]
    timestamp: datetime
    user_email: Optional[str] = None

    model_config = {"from_attributes": True}


class PaginatedAuditLogs(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[AuditLogOut]
