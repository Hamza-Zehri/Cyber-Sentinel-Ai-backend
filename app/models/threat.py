import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Float, Integer
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Threat(Base):
    """Aggregated threat-intelligence records (used for the world map / stats)."""
    __tablename__ = "threats"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    source_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    country: Mapped[str] = mapped_column(String(100), nullable=True)
    country_code: Mapped[str] = mapped_column(String(4), nullable=True)
    latitude: Mapped[float] = mapped_column(Float, nullable=True)
    longitude: Mapped[float] = mapped_column(Float, nullable=True)

    threat_level: Mapped[str] = mapped_column(String(20), nullable=False, default="low")
    attack_count: Mapped[int] = mapped_column(Integer, default=1)
    threat_category: Mapped[str] = mapped_column(String(100), nullable=True)

    first_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"<Threat {self.source_ip} {self.threat_level}>"
