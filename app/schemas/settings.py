from typing import Optional
from pydantic import BaseModel, Field


class SettingOut(BaseModel):
    id: str
    key: str
    value: Optional[str]
    category: str

    model_config = {"from_attributes": True}


class SettingUpdate(BaseModel):
    value: Optional[str] = None
    category: Optional[str] = Field(None, max_length=50)


class SettingCreate(BaseModel):
    key: str = Field(min_length=1, max_length=150)
    value: Optional[str] = None
    category: str = Field(default="general", max_length=50)
