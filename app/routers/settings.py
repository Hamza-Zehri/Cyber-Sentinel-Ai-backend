"""
Cyber Sentinel AI - Settings router.
CRUD for system-wide key/value settings.
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.core.deps import get_current_active_user, require_permission
from app.database import get_db
from app.models.role import PermissionCode
from app.models.setting import SystemSetting
from app.models.user import User
from app.schemas.settings import SettingCreate, SettingOut, SettingUpdate
from app.services.audit import log_action

router = APIRouter(prefix="/settings", tags=["Settings"])


@router.get("", response_model=list[SettingOut])
def list_settings(
    category: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_active_user),
):
    q = db.query(SystemSetting)
    if category:
        q = q.filter(SystemSetting.category == category)
    settings = q.order_by(SystemSetting.category, SystemSetting.key).all()
    return [
        SettingOut(id=str(s.id), key=s.key, value=s.value, category=s.category)
        for s in settings
    ]


@router.post("", response_model=SettingOut)
def create_setting(
    payload: SettingCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(PermissionCode.MANAGE_SETTINGS)),
):
    if db.query(SystemSetting).filter(SystemSetting.key == payload.key).first():
        raise HTTPException(status_code=400, detail="Setting key already exists")
    s = SystemSetting(key=payload.key, value=payload.value, category=payload.category)
    db.add(s)
    db.commit()
    db.refresh(s)
    log_action(db, action="create_setting", module="settings", user_id=current_user.id,
               details=f"key={s.key}")
    return SettingOut(id=str(s.id), key=s.key, value=s.value, category=s.category)


@router.patch("/{setting_id}", response_model=SettingOut)
def update_setting(
    setting_id: uuid.UUID,
    payload: SettingUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(PermissionCode.MANAGE_SETTINGS)),
):
    s = db.query(SystemSetting).filter(SystemSetting.id == setting_id).first()
    if not s:
        raise HTTPException(status_code=404, detail="Setting not found")
    if payload.value is not None:
        s.value = payload.value
    if payload.category is not None:
        s.category = payload.category
    s.updated_at = __import__("datetime").datetime.utcnow()
    db.commit()
    db.refresh(s)
    log_action(db, action="update_setting", module="settings", user_id=current_user.id,
               details=f"key={s.key}")
    return SettingOut(id=str(s.id), key=s.key, value=s.value, category=s.category)
