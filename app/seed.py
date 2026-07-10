"""
Cyber Sentinel AI - Idempotent database seeding.
Creates default Roles, Permissions, role-permission mappings, and a
bootstrap Admin account (credentials configurable via env vars).
Safe to run on every startup — it only inserts what is missing.
"""
import os
import logging

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.security import hash_password
from app.models.role import Permission, PermissionCode, Role, RoleName
from app.models.user import User

logger = logging.getLogger("cybersentinel.seed")

ROLE_PERMISSIONS = {
    RoleName.ADMIN: [
        PermissionCode.MANAGE_USERS, PermissionCode.MANAGE_ROLES, PermissionCode.MANAGE_SETTINGS,
        PermissionCode.VIEW_DASHBOARD, PermissionCode.MANAGE_NETWORK_MONITOR, PermissionCode.MANAGE_ALERTS,
        PermissionCode.RUN_AI_SCANS, PermissionCode.VIEW_REPORTS, PermissionCode.GENERATE_REPORTS,
        PermissionCode.MANAGE_BACKUPS, PermissionCode.VIEW_AUDIT_LOGS,
    ],
    RoleName.SECURITY_ANALYST: [
        PermissionCode.VIEW_DASHBOARD, PermissionCode.MANAGE_NETWORK_MONITOR, PermissionCode.MANAGE_ALERTS,
        PermissionCode.RUN_AI_SCANS, PermissionCode.VIEW_REPORTS, PermissionCode.GENERATE_REPORTS,
    ],
    RoleName.VIEWER: [
        PermissionCode.VIEW_DASHBOARD, PermissionCode.VIEW_REPORTS,
    ],
}

ALL_PERMISSIONS = {
    PermissionCode.MANAGE_USERS: "Create, update, deactivate users",
    PermissionCode.MANAGE_ROLES: "Assign roles and permissions",
    PermissionCode.MANAGE_SETTINGS: "Change system-wide settings",
    PermissionCode.VIEW_DASHBOARD: "View the main dashboard",
    PermissionCode.MANAGE_NETWORK_MONITOR: "Start/stop packet capture, view live traffic",
    PermissionCode.MANAGE_ALERTS: "Acknowledge, resolve, and configure alerts",
    PermissionCode.RUN_AI_SCANS: "Run phishing/malware/password AI scans",
    PermissionCode.VIEW_REPORTS: "View generated reports",
    PermissionCode.GENERATE_REPORTS: "Generate new PDF/CSV/Excel reports",
    PermissionCode.MANAGE_BACKUPS: "Trigger and restore backups",
    PermissionCode.VIEW_AUDIT_LOGS: "View system audit logs",
}


def seed_roles_and_permissions(db: Session) -> None:
    code_to_permission = {}
    for code, description in ALL_PERMISSIONS.items():
        perm = db.scalar(select(Permission).where(Permission.code == code))
        if perm is None:
            perm = Permission(code=code, description=description)
            db.add(perm)
            db.flush()
        code_to_permission[code] = perm

    for role_name, perm_codes in ROLE_PERMISSIONS.items():
        role = db.scalar(select(Role).where(Role.name == role_name))
        if role is None:
            role = Role(name=role_name, description=f"{role_name.replace('_', ' ').title()} role")
            db.add(role)
            db.flush()
        role.permissions = [code_to_permission[c] for c in perm_codes]

    db.commit()


def seed_admin_user(db: Session) -> None:
    admin_email = os.getenv("DEFAULT_ADMIN_EMAIL", "admin@cybersentinel.ai")
    admin_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "ChangeMe123!")

    existing = db.scalar(select(User).where(User.email == admin_email))
    if existing:
        return

    admin_role = db.scalar(select(Role).where(Role.name == RoleName.ADMIN))
    if admin_role is None:
        logger.warning("Admin role missing; run seed_roles_and_permissions first.")
        return

    admin = User(
        full_name="System Administrator",
        email=admin_email,
        hashed_password=hash_password(admin_password),
        role_id=admin_role.id,
        is_active=True,
        is_verified=True,
    )
    db.add(admin)
    db.commit()
    logger.info("Seeded default admin account: %s", admin_email)


def run_all_seeds(db: Session) -> None:
    seed_roles_and_permissions(db)
    seed_admin_user(db)
