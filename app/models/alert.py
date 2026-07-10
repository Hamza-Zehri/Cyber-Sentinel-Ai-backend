import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Boolean, Text
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    alert_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # e.g. port_scan, syn_flood, udp_flood, icmp_flood, fin_scan, null_scan, xmas_scan,
    # brute_force, network_scan, arp_spoofing, dns_spoofing, suspicious_connection,
    # repeated_failed_connection, bandwidth_abuse, data_exfiltration, login_anomaly, malware, phishing

    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="medium")  # low/medium/high/critical
    source_ip: Mapped[str] = mapped_column(String(64), nullable=True, index=True)
    target_ip: Mapped[str] = mapped_column(String(64), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    is_resolved: Mapped[bool] = mapped_column(Boolean, default=False)
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    def __repr__(self) -> str:
        return f"<Alert {self.alert_type} sev={self.severity}>"
