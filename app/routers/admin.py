"""
Cyber Sentinel AI - Admin Panel router.
User management, role management, audit log viewer.
"""
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session, joinedload

from app.core.deps import get_current_active_user, require_permission
from app.core.security import hash_password
from app.database import get_db
from app.models.audit_log import AuditLog
from app.models.role import Permission, PermissionCode, Role, RoleName
from app.models.user import User
from app.schemas.admin import (
    AuditLogOut,
    PaginatedAuditLogs,
    RoleCreate,
    RoleOut,
    RoleUpdate,
    UserOut,
    UserUpdate,
)
from app.services.audit import log_action

router = APIRouter(prefix="/admin", tags=["Admin"])


# --- Users ---

@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_USERS)),
):
    users = db.query(User).options(joinedload(User.role)).all()
    return [
        UserOut(
            id=str(u.id), full_name=u.full_name, email=u.email,
            role=u.role.name, is_active=u.is_active,
            is_verified=u.is_verified, created_at=u.created_at,
        )
        for u in users
    ]


@router.get("/users/{user_id}", response_model=UserOut)
def get_user(
    user_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_USERS)),
):
    u = db.query(User).options(joinedload(User.role)).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    return UserOut(
        id=str(u.id), full_name=u.full_name, email=u.email,
        role=u.role.name, is_active=u.is_active,
        is_verified=u.is_verified, created_at=u.created_at,
    )


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: uuid.UUID,
    payload: UserUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(PermissionCode.MANAGE_USERS)),
):
    u = db.query(User).options(joinedload(User.role)).filter(User.id == user_id).first()
    if not u:
        raise HTTPException(status_code=404, detail="User not found")
    if payload.full_name is not None:
        u.full_name = payload.full_name
    if payload.is_active is not None:
        u.is_active = payload.is_active
    if payload.role_name is not None:
        role = db.query(Role).filter(Role.name == payload.role_name).first()
        if not role:
            raise HTTPException(status_code=404, detail="Role not found")
        u.role_id = role.id
    db.commit()
    db.refresh(u)
    log_action(db, action="update_user", module="admin", user_id=current_user.id,
               details=f"updated user {u.email}")
    return UserOut(
        id=str(u.id), full_name=u.full_name, email=u.email,
        role=u.role.name, is_active=u.is_active,
        is_verified=u.is_verified, created_at=u.created_at,
    )


# --- Roles ---

@router.get("/roles", response_model=list[RoleOut])
def list_roles(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_ROLES)),
):
    roles = db.query(Role).options(joinedload(Role.permissions)).all()
    return [
        RoleOut(
            id=str(r.id), name=r.name, description=r.description,
            permission_codes=[p.code for p in r.permissions],
        )
        for r in roles
    ]


@router.post("/roles", response_model=RoleOut)
def create_role(
    payload: RoleCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(PermissionCode.MANAGE_ROLES)),
):
    if db.query(Role).filter(Role.name == payload.name).first():
        raise HTTPException(status_code=400, detail="Role already exists")
    role = Role(name=payload.name, description=payload.description)
    if payload.permission_codes:
        perms = db.query(Permission).filter(Permission.code.in_(payload.permission_codes)).all()
        role.permissions = perms
    db.add(role)
    db.commit()
    db.refresh(role)
    log_action(db, action="create_role", module="admin", user_id=current_user.id,
               details=f"created role {role.name}")
    return RoleOut(
        id=str(role.id), name=role.name, description=role.description,
        permission_codes=payload.permission_codes,
    )


@router.patch("/roles/{role_id}", response_model=RoleOut)
def update_role(
    role_id: uuid.UUID,
    payload: RoleUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(require_permission(PermissionCode.MANAGE_ROLES)),
):
    role = db.query(Role).options(joinedload(Role.permissions)).filter(Role.id == role_id).first()
    if not role:
        raise HTTPException(status_code=404, detail="Role not found")
    if role.name in (RoleName.ADMIN, RoleName.VIEWER, RoleName.SECURITY_ANALYST):
        if payload.permission_codes is not None:
            perms = db.query(Permission).filter(Permission.code.in_(payload.permission_codes)).all()
            role.permissions = perms
        if payload.description is not None:
            role.description = payload.description
        db.commit()
        db.refresh(role)
        log_action(db, action="update_role", module="admin", user_id=current_user.id,
                   details=f"updated role {role.name}")
    else:
        if payload.description is not None:
            role.description = payload.description
        if payload.permission_codes is not None:
            perms = db.query(Permission).filter(Permission.code.in_(payload.permission_codes)).all()
            role.permissions = perms
        db.commit()
        db.refresh(role)
        log_action(db, action="update_role", module="admin", user_id=current_user.id,
                   details=f"updated role {role.name}")
    return RoleOut(
        id=str(role.id), name=role.name, description=role.description,
        permission_codes=[p.code for p in role.permissions],
    )


# --- Audit Logs ---

@router.get("/audit-logs", response_model=PaginatedAuditLogs)
def list_audit_logs(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    module: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.VIEW_AUDIT_LOGS)),
):
    q = db.query(AuditLog)
    if module:
        q = q.filter(AuditLog.module == module)
    if action:
        q = q.filter(AuditLog.action == action)
    total = q.count()
    logs = q.order_by(AuditLog.timestamp.desc()).offset((page - 1) * page_size).limit(page_size).all()
    items = []
    for log in logs:
        user_email = None
        if log.user_id:
            u = db.query(User).filter(User.id == log.user_id).first()
            if u:
                user_email = u.email
        items.append(AuditLogOut(
            id=str(log.id), user_id=str(log.user_id) if log.user_id else None,
            action=log.action, module=log.module, ip_address=log.ip_address,
            result=log.result, details=log.details, timestamp=log.timestamp,
            user_email=user_email,
        ))
    return PaginatedAuditLogs(total=total, page=page, page_size=page_size, items=items)
