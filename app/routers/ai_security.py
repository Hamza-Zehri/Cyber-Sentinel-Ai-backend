"""
Cyber Sentinel AI - AI Security Modules router.
Phishing URL detection, malware file scanning, and password strength analysis.
"""
import tempfile
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile
from sqlalchemy.orm import Session

from app.core.deps import get_current_active_user, require_permission
from app.database import get_db
from app.ml.malware_predictor import analyze_file, quarantine_file
from app.ml.password_analyzer import analyze_password
from app.ml.phishing_predictor import predict_url
from app.models.ml_prediction import MLPrediction
from app.models.role import PermissionCode
from app.models.user import User
from app.schemas.ai import (
    MalwareScanResponse,
    PasswordAnalyzeRequest,
    PasswordAnalyzeResponse,
    PhishingCheckRequest,
    PhishingCheckResponse,
)
from app.services.audit import log_action

router = APIRouter(prefix="/ai", tags=["AI Security Modules"])

MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB


@router.post("/phishing/check", response_model=PhishingCheckResponse)
def check_phishing_url(
    payload: PhishingCheckRequest,
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.RUN_AI_SCANS)),
):
    try:
        result = predict_url(payload.url)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))

    db.add(MLPrediction(
        model_type="phishing_url",
        input_reference=payload.url,
        prediction_label=result["label"],
        risk_score=result["risk_score"],
        confidence=result["confidence"],
        explanation=result["explanation"],
    ))
    db.commit()

    log_action(db, action="phishing_check", module="ai_phishing", user_id=user.id,
               details=f"url={payload.url} label={result['label']}")

    return PhishingCheckResponse(
        url=result["url"], label=result["label"], risk_score=result["risk_score"],
        confidence=result["confidence"], reasons=result["reasons"], explanation=result["explanation"],
    )


@router.post("/malware/scan", response_model=MalwareScanResponse)
def scan_file_for_malware(
    file: UploadFile = File(...),
    quarantine: bool = Query(False, description="Automatically quarantine if flagged malicious/suspicious"),
    db: Session = Depends(get_db),
    user: User = Depends(require_permission(PermissionCode.RUN_AI_SCANS)),
):
    contents = file.file.read()
    if len(contents) > MAX_UPLOAD_BYTES:
        raise HTTPException(status_code=413, detail="File exceeds 50MB scan limit")
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    with tempfile.NamedTemporaryFile(delete=False, suffix=Path(file.filename).suffix) as tmp:
        tmp.write(contents)
        tmp_path = tmp.name

    try:
        result = analyze_file(tmp_path)
        result["filename"] = file.filename  # preserve original name, not the temp path's

        quarantined = False
        quarantine_path = None
        if quarantine and result["label"] in ("malicious", "suspicious"):
            quarantine_path = quarantine_file(tmp_path)
            quarantined = True
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    finally:
        if Path(tmp_path).exists():
            Path(tmp_path).unlink()

    db.add(MLPrediction(
        model_type="malware_file",
        input_reference=f"{file.filename} ({result['sha256'][:16]}...)",
        prediction_label=result["label"],
        risk_score=result["malware_probability"],
        confidence=result["confidence"],
        explanation="; ".join(result["reasons"]),
    ))
    db.commit()

    log_action(db, action="malware_scan", module="ai_malware", user_id=user.id,
               details=f"file={file.filename} label={result['label']} sha256={result['sha256']}")

    return MalwareScanResponse(**result, quarantined=quarantined, quarantine_path=quarantine_path)


@router.post("/password/analyze", response_model=PasswordAnalyzeResponse)
def analyze_password_strength(
    payload: PasswordAnalyzeRequest,
    user: User = Depends(get_current_active_user),
):
    # Intentionally not logged/persisted anywhere — the raw password never touches the audit log or DB.
    result = analyze_password(payload.password)
    return PasswordAnalyzeResponse(**result)
