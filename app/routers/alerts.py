"""
Cyber Sentinel AI - Alerts router.
"""
import uuid
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.deps import get_current_active_user, require_permission
from app.database import get_db
from app.models.alert import Alert
from app.models.role import PermissionCode
from app.models.user import User
from app.schemas.network import AlertOut, PaginatedAlerts
from app.services.audit import log_action

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=PaginatedAlerts)
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    is_resolved: Optional[bool] = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if alert_type:
        stmt = stmt.where(Alert.alert_type == alert_type)
    if is_resolved is not None:
        stmt = stmt.where(Alert.is_resolved == is_resolved)

    total = db.scalar(select(func.count()).select_from(stmt.subquery()))
    stmt = stmt.order_by(Alert.timestamp.desc()).offset((page - 1) * page_size).limit(page_size)
    items = db.scalars(stmt).all()

    return PaginatedAlerts(total=total or 0, page=page, page_size=page_size, items=items)


@router.post("/{alert_id}/resolve", response_model=AlertOut)
def resolve_alert(
    alert_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_ALERTS)),
):
    alert = db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.is_resolved = True
    alert.resolved_at = datetime.utcnow()
    db.commit()
    db.refresh(alert)
    log_action(db, action="resolve_alert", module="alerts", user_id=user.id, details=str(alert_id))
    return alert
