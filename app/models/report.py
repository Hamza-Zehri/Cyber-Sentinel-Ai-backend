import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, ForeignKey
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    generated_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), nullable=True)

    report_type: Mapped[str] = mapped_column(String(50), nullable=False)  # incident/threat/network
    period: Mapped[str] = mapped_column(String(20), nullable=False)  # daily/weekly/monthly/custom
    file_format: Mapped[str] = mapped_column(String(10), nullable=False)  # pdf/csv/xlsx
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Report {self.report_type} {self.file_format}>"
