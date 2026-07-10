import uuid
from datetime import datetime

from sqlalchemy import String, DateTime, Float, Text
from sqlalchemy import Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base


class MLPrediction(Base):
    """Stores every AI/ML prediction made (phishing URL, malware file, etc.) for audit/history."""
    __tablename__ = "ml_predictions"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    model_type: Mapped[str] = mapped_column(String(50), nullable=False)  # phishing_url / malware_file
    input_reference: Mapped[str] = mapped_column(String(500), nullable=False)  # url or filename/hash

    prediction_label: Mapped[str] = mapped_column(String(50), nullable=False)  # safe/suspicious/phishing/malicious
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)

    def __repr__(self) -> str:
        return f"<MLPrediction {self.model_type} {self.prediction_label}>"
