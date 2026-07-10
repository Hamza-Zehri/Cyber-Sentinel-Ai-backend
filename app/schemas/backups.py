from datetime import datetime
from pydantic import BaseModel


class BackupOut(BaseModel):
    filename: str
    size_bytes: int
    created_at: datetime

    model_config = {"from_attributes": True}


class BackupList(BaseModel):
    backups: list[BackupOut]
    backup_dir: str
