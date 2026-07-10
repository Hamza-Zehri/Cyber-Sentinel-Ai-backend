"""
Cyber Sentinel AI - Network Monitor router.
Controls live packet capture and exposes captured packets for the dashboard.
"""
import socket
import subprocess
import re
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_current_active_user, require_permission
from app.database import get_db
from app.models.packet import Packet
from app.models.role import PermissionCode
from app.models.user import User
from app.schemas.network import (
    CaptureStartRequest,
    CaptureStatusResponse,
    InterfaceInfo,
    PacketOut,
    PaginatedPackets,
)
from app.services.audit import log_action
from app.services.packet_capture import capture_session

router = APIRouter(prefix="/network", tags=["Network Monitor"])


@router.get("/interfaces", response_model=list[InterfaceInfo])
def list_interfaces(user: User = Depends(get_current_active_user)):
    try:
        result = subprocess.run(
            ["netsh", "interface", "ip", "show", "interfaces"],
            capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.splitlines()
    except Exception:
        return []

    interfaces = []
    for line in lines:
        m = re.match(r'^\s*(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(.*)', line)
        if m:
            state = m.group(4).lower()
            name = m.group(5).strip()
            if name and not name.startswith("Loopback"):
                interfaces.append(InterfaceInfo(
                    name=name,
                    connected=state == "connected",
                    mtu=int(m.group(3)),
                    metric=int(m.group(2)),
                ))
    return interfaces


@router.post("/capture/start", response_model=CaptureStatusResponse)
def start_capture(
    payload: CaptureStartRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_NETWORK_MONITOR)),
):
    try:
        capture_session.start(interface=payload.interface)
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    log_action(db, action="start_capture", module="network_monitor", user_id=user.id,
               details=f"interface={payload.interface}")
    return CaptureStatusResponse(**capture_session.status())


@router.post("/capture/stop", response_model=CaptureStatusResponse)
def stop_capture(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_NETWORK_MONITOR)),
):
    capture_session.stop()
    log_action(db, action="stop_capture", module="network_monitor", user_id=user.id)
    return CaptureStatusResponse(**capture_session.status())


@router.get("/capture/status", response_model=CaptureStatusResponse)
def capture_status(user: User = Depends(get_current_active_user)):
    return CaptureStatusResponse(**capture_session.status())


@router.get("/packets", response_model=PaginatedPackets)
def list_packets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    stmt = select(Packet)
    if src_ip:
        stmt = stmt.where(Packet.src_ip == src_ip)
    if dst_ip:
        stmt = stmt.where(Packet.dst_ip == dst_ip)
    if protocol:
        stmt = stmt.where(Packet.protocol == protocol.upper())

    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    stmt = stmt.order_by(Packet.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
    items = db.scalars(stmt).all()

    return PaginatedPackets(total=total or 0, page=page, page_size=page_size, items=items)


@router.delete("/packets")
def clear_packets(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_NETWORK_MONITOR)),
):
    count = db.query(Packet).delete()
    db.commit()
    log_action(db, action="clear_packets", module="network_monitor", user_id=user.id,
               details=f"deleted {count} packets")
    return {"deleted": count}


@router.get("/resolve")
def resolve_host(ip: str = Query(...), user: User = Depends(get_current_active_user)):
    hostname = None
    vendor = None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except Exception:
        try:
            result = subprocess.run(["nslookup", ip], capture_output=True, text=True, timeout=3)
            for line in result.stdout.splitlines():
                m = re.search(r'Name:\s+(.+)', line)
                if m:
                    hostname = m.group(1).strip()
                    break
        except Exception:
            pass
    try:
        result = subprocess.run(["arp", "-a", ip], capture_output=True, text=True, timeout=3)
        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == ip:
                vendor = _mac_vendor(parts[1])
                break
    except Exception:
        pass
    return {"ip": ip, "hostname": hostname, "vendor": vendor}


MAC_VENDORS = {
    "E0:2E:0B": "Intel", "00:0F:00": "Realtek", "74:5D:22": "Realtek",
    "00:15:5D": "Hyper-V", "00:50:56": "VMware", "00:0C:29": "VMware",
    "08:00:27": "Oracle/VB", "00:1A:4B": "Raspberry Pi", "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi", "00:1B:44": "Huawei", "F8:59:71": "Xiaomi",
    "18:FE:34": "Samsung", "AC:84:C6": "Apple", "F0:18:98": "Apple",
    "A4:D9:31": "Cisco", "00:26:AB": "Cisco", "00:24:97": "Hewlett Packard",
    "10:1F:74": "Netgear", "C0:3F:0E": "TP-Link", "50:C7:BF": "TP-Link",
    "F4:F2:6D": "D-Link", "00:24:01": "Dell", "F8:BC:12": "Dell",
    "34:DE:1A": "Intel", "3C:DF:1E": "Intel", "A0:36:9F": "Intel",
    "00:1E:4C": "Synology", "00:11:32": "ASUS",
}


def _mac_vendor(mac: str) -> str | None:
    oui = mac.upper()[:8]
    return MAC_VENDORS.get(oui)
