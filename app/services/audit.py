"""
Cyber Sentinel AI - Audit logging service
Every significant action in the platform must call log_action() so it is
recorded in the audit_logs table (timestamp, user, action, module, ip, result).
"""
import uuid
from typing import Optional

from sqlalchemy.orm import Session

from app.models.audit_log import AuditLog


def log_action(
    db: Session,
    *,
    action: str,
    module: str,
    user_id: Optional[uuid.UUID] = None,
    ip_address: Optional[str] = None,
    result: str = "success",
    details: Optional[str] = None,
) -> AuditLog:
    entry = AuditLog(
        user_id=user_id,
        action=action,
        module=module,
        ip_address=ip_address,
        result=result,
        details=details,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry
