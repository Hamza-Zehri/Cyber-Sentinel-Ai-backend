"""
Cyber Sentinel AI - Backups router.
Database backup and restore operations.
"""
import os
import shutil
import time
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.core.deps import get_current_active_user, require_permission
from app.database import engine, get_db
from app.models.role import PermissionCode
from app.models.user import User
from app.schemas.backups import BackupList, BackupOut
from app.services.audit import log_action

router = APIRouter(prefix="/backups", tags=["Backups"])

BACKUP_DIR = Path(__file__).resolve().parents[2] / "backups"
BACKUP_DIR.mkdir(parents=True, exist_ok=True)


@router.post("/create")
def create_backup(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_BACKUPS)),
):
    if str(engine.url).startswith("sqlite"):
        db_path = str(engine.url).replace("sqlite:///", "")
        if not os.path.exists(db_path):
            raise HTTPException(status_code=404, detail="Database file not found")
        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f"backup_{timestamp}.db"
        dest = BACKUP_DIR / filename
        shutil.copy2(db_path, dest)
        size_bytes = os.path.getsize(dest)
        log_action(db, action="create_backup", module="backups", user_id=user.id,
                   details=f"file={filename} size={size_bytes}")
        return {
            "filename": filename,
            "size_bytes": size_bytes,
            "created_at": datetime.utcnow().isoformat(),
        }
    raise HTTPException(status_code=501, detail="Backup for PostgreSQL not yet implemented")


@router.get("", response_model=BackupList)
def list_backups(
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_BACKUPS)),
):
    files = sorted(BACKUP_DIR.iterdir(), key=os.path.getmtime, reverse=True) if BACKUP_DIR.exists() else []
    backups = []
    for f in files:
        if f.is_file():
            mtime = os.path.getmtime(f)
            backups.append(BackupOut(
                filename=f.name,
                size_bytes=os.path.getsize(f),
                created_at=datetime.fromtimestamp(mtime),
            ))
    return BackupList(backups=backups, backup_dir=str(BACKUP_DIR))


@router.get("/download/{filename}")
def download_backup(
    filename: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_BACKUPS)),
):
    filepath = BACKUP_DIR / filename
    if not filepath.exists() or not filepath.is_file():
        raise HTTPException(status_code=404, detail="Backup file not found")
    return FileResponse(str(filepath), filename=filename, media_type="application/octet-stream")


@router.post("/restore/{filename}")
def restore_backup(
    filename: str,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.MANAGE_BACKUPS)),
):
    if str(engine.url).startswith("sqlite"):
        filepath = BACKUP_DIR / filename
        if not filepath.exists():
            raise HTTPException(status_code=404, detail="Backup file not found")
        db_path = str(engine.url).replace("sqlite:///", "")
        # Close all connections and restore
        shutil.copy2(str(filepath), db_path)
        log_action(db, action="restore_backup", module="backups", user_id=user.id,
                   details=f"file={filename}")
        return {"status": "ok", "message": f"Database restored from {filename}"}
    raise HTTPException(status_code=501, detail="Restore for PostgreSQL not yet implemented")
