import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class InterfaceInfo(BaseModel):
    name: str
    connected: bool
    mtu: int
    metric: int


class CaptureStartRequest(BaseModel):
    interface: Optional[str] = None


class CaptureStatusResponse(BaseModel):
    is_running: bool
    interface: Optional[str]
    packets_captured: int
    alerts_raised: int


class PacketOut(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: str
    size_bytes: int
    ttl: Optional[int]
    flags: Optional[str]
    mac_address: Optional[str]

    model_config = {"from_attributes": True}


class AlertOut(BaseModel):
    id: uuid.UUID
    timestamp: datetime
    alert_type: str
    severity: str
    source_ip: Optional[str]
    target_ip: Optional[str]
    description: str
    is_resolved: bool
    resolved_at: Optional[datetime]

    model_config = {"from_attributes": True}


class PaginatedPackets(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[PacketOut]


class PaginatedAlerts(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[AlertOut]
