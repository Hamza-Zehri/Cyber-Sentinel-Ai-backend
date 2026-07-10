from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


class ReportOut(BaseModel):
    id: str
    report_type: str
    period: str
    file_format: str
    file_path: str
    generated_by: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


class ReportGenerateRequest(BaseModel):
    report_type: str = Field(pattern=r"^(incident|threat|network|ai_scan)$")
    period: str = Field(default="daily", pattern=r"^(daily|weekly|monthly|custom)$")
    file_format: str = Field(default="pdf", pattern=r"^(pdf|csv|xlsx)$")


class PaginatedReports(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[ReportOut]
