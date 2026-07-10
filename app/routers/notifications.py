"""
Cyber Sentinel AI - Notifications router.
In-app notification system.
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.deps import get_current_active_user
from app.database import get_db
from app.models.notification import Notification
from app.models.user import User
from app.schemas.notifications import NotificationOut, PaginatedNotifications

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("", response_model=PaginatedNotifications)
def list_notifications(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    unread_only: bool = Query(False),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    q = db.query(Notification).filter(
        (Notification.user_id == user.id) | (Notification.user_id.is_(None))
    )
    if unread_only:
        q = q.filter(Notification.is_read == False)
    total = q.count()
    notifications = (
        q.order_by(Notification.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return PaginatedNotifications(
        total=total,
        page=page,
        page_size=page_size,
        items=[
            NotificationOut(
                id=str(n.id), user_id=str(n.user_id) if n.user_id else None,
                title=n.title, message=n.message, notification_type=n.notification_type,
                is_read=n.is_read, created_at=n.created_at,
            )
            for n in notifications
        ],
    )


@router.get("/unread-count")
def unread_count(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    count = (
        db.query(Notification)
        .filter(
            (Notification.user_id == user.id) | (Notification.user_id.is_(None)),
            Notification.is_read == False,
        )
        .count()
    )
    return {"unread_count": count}


@router.post("/{notification_id}/read")
def mark_read(
    notification_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    n = db.query(Notification).filter(Notification.id == notification_id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found")
    n.is_read = True
    db.commit()
    return {"status": "ok"}


@router.post("/mark-all-read")
def mark_all_read(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    db.query(Notification).filter(
        (Notification.user_id == user.id) | (Notification.user_id.is_(None)),
        Notification.is_read == False,
    ).update({Notification.is_read: True})
    db.commit()
    return {"status": "ok"}
