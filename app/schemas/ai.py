from typing import Optional

from pydantic import BaseModel, Field


class PhishingCheckRequest(BaseModel):
    url: str = Field(min_length=3, max_length=2048)


class PhishingCheckResponse(BaseModel):
    url: str
    label: str
    risk_score: float
    confidence: float
    reasons: list[str]
    explanation: str


class MalwareScanResponse(BaseModel):
    filename: str
    sha256: str
    md5: str
    size_bytes: int
    entropy: float
    label: str
    malware_probability: float
    confidence: float
    reasons: list[str]
    quarantined: bool = False
    quarantine_path: Optional[str] = None


class PasswordAnalyzeRequest(BaseModel):
    password: str = Field(min_length=1, max_length=256)


class PasswordAnalyzeResponse(BaseModel):
    length: int
    entropy_bits: float
    strength: str
    is_common_password: bool
    has_sequential_pattern: bool
    has_repeated_characters: bool
    has_keyboard_pattern: bool
    estimated_crack_time: str
    recommendations: list[str]
