import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Integer, BigInteger
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Packet(Base):
    __tablename__ = "packets"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    src_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    dst_ip: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    src_port: Mapped[int] = mapped_column(Integer, nullable=True)
    dst_port: Mapped[int] = mapped_column(Integer, nullable=True)
    protocol: Mapped[str] = mapped_column(String(20), nullable=False)  # TCP/UDP/ICMP/ARP...

    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    ttl: Mapped[int] = mapped_column(Integer, nullable=True)
    flags: Mapped[str] = mapped_column(String(50), nullable=True)
    mac_address: Mapped[str] = mapped_column(String(64), nullable=True)

    total_seen_bytes: Mapped[int] = mapped_column(BigInteger, default=0)

    def __repr__(self) -> str:
        return f"<Packet {self.src_ip}->{self.dst_ip} {self.protocol}>"
