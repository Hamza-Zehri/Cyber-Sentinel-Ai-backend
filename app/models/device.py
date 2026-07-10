import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, ForeignKey, Boolean
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Device(Base):
    """Known devices per-user, used for login anomaly detection ('unknown device')."""
    __tablename__ = "devices"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id", ondelete="CASCADE"))

    device_fingerprint: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    device_name: Mapped[str] = mapped_column(String(255), nullable=True)
    browser: Mapped[str] = mapped_column(String(100), nullable=True)
    os: Mapped[str] = mapped_column(String(100), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(500), nullable=True)
    is_trusted: Mapped[bool] = mapped_column(Boolean, default=False)

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Device {self.device_fingerprint[:12]}>"
