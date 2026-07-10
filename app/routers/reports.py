"""
Cyber Sentinel AI - Reports router.
Generate and list reports in PDF, CSV, or XLSX format.
"""
import csv
import io
import os
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session, joinedload

from app.core.deps import get_current_active_user, require_permission
from app.database import get_db
from app.models.alert import Alert
from app.models.ml_prediction import MLPrediction
from app.models.packet import Packet
from app.models.report import Report
from app.models.role import PermissionCode
from app.models.user import User
from app.schemas.reports import PaginatedReports, ReportGenerateRequest, ReportOut
from app.services.audit import log_action

router = APIRouter(prefix="/reports", tags=["Reports"])

REPORTS_DIR = Path(__file__).resolve().parents[2] / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)


def _generate_csv(report_type: str, period: str, db: Session) -> tuple[str, str]:
    now = datetime.utcnow()
    if period == "daily":
        since = now - timedelta(days=1)
    elif period == "weekly":
        since = now - timedelta(weeks=1)
    elif period == "monthly":
        since = now - timedelta(days=30)
    else:
        since = datetime(2000, 1, 1)

    filename = f"{report_type}_{period}_{now.strftime('%Y%m%d_%H%M%S')}.csv"
    filepath = str(REPORTS_DIR / filename)

    if report_type == "alert":
        rows = db.query(Alert).filter(Alert.timestamp >= since).all()
        with open(filepath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ID", "Timestamp", "Type", "Severity", "Source IP", "Target IP", "Description", "Resolved"])
            for r in rows:
                w.writerow([r.id, r.timestamp, r.alert_type, r.severity, r.source_ip, r.target_ip, r.description, r.is_resolved])
    elif report_type == "network":
        rows = db.query(Packet).filter(Packet.timestamp >= since).all()
        with open(filepath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ID", "Timestamp", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Size"])
            for r in rows:
                w.writerow([r.id, r.timestamp, r.src_ip, r.dst_ip, r.src_port, r.dst_port, r.protocol, r.size_bytes])
    elif report_type == "ai_scan":
        rows = db.query(MLPrediction).filter(MLPrediction.created_at >= since).all()
        with open(filepath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ID", "Model", "Input", "Label", "Risk Score", "Confidence", "Created"])
            for r in rows:
                w.writerow([r.id, r.model_type, r.input_reference, r.prediction_label, r.risk_score, r.confidence, r.created_at])
    else:
        rows = db.query(Alert).filter(Alert.timestamp >= since).all()
        with open(filepath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["ID", "Timestamp", "Type", "Severity", "Source IP", "Description"])
            for r in rows:
                w.writerow([r.id, r.timestamp, r.alert_type, r.severity, r.source_ip, r.description])

    return filepath, filename


@router.post("/generate")
def generate_report(
    payload: ReportGenerateRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.GENERATE_REPORTS)),
):
    if payload.file_format == "pdf":
        raise HTTPException(status_code=501, detail="PDF generation not yet implemented")
    if payload.file_format == "xlsx":
        raise HTTPException(status_code=501, detail="XLSX generation not yet implemented")

    filepath, filename = _generate_csv(payload.report_type, payload.period, db)

    report = Report(
        report_type=payload.report_type,
        period=payload.period,
        file_format=payload.file_format,
        file_path=filepath,
        generated_by=user.id,
    )
    db.add(report)
    db.commit()
    db.refresh(report)

    log_action(db, action="generate_report", module="reports", user_id=user.id,
               details=f"type={payload.report_type} format={payload.file_format}")

    return {
        "id": str(report.id),
        "report_type": report.report_type,
        "period": report.period,
        "file_format": report.file_format,
        "file_path": report.file_path,
        "created_at": report.created_at.isoformat(),
        "filename": filename,
    }


@router.get("", response_model=PaginatedReports)
def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.VIEW_REPORTS)),
):
    total = db.query(Report).count()
    reports = (
        db.query(Report)
        .order_by(Report.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return PaginatedReports(
        total=total,
        page=page,
        page_size=page_size,
        items=[
            ReportOut(
                id=str(r.id), report_type=r.report_type, period=r.period,
                file_format=r.file_format, file_path=r.file_path,
                generated_by=str(r.generated_by) if r.generated_by else None,
                created_at=r.created_at,
            )
            for r in reports
        ],
    )


@router.get("/download/{report_id}")
def download_report(
    report_id: uuid.UUID,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.VIEW_REPORTS)),
):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not os.path.exists(report.file_path):
        raise HTTPException(status_code=404, detail="Report file not found on disk")
    return FileResponse(
        report.file_path,
        filename=os.path.basename(report.file_path),
        media_type="application/octet-stream",
    )
