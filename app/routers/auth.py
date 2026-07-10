"""
Cyber Sentinel AI - Authentication router
Implements: Register, Login, Refresh Token, Logout, Forgot Password,
Reset Password, Email Verification, RBAC-aware JWT issuance.
"""
import hashlib
import logging
from datetime import datetime, timedelta, timezone

logger = logging.getLogger("cybersentinel.auth")

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.deps import get_current_active_user
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_random_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.database import get_db
from app.models.device import Device
from app.models.role import Role, RoleName
from app.models.session import UserSession
from app.models.user import User
from app.schemas.auth import (
    ForgotPasswordRequest,
    LoginRequest,
    MessageResponse,
    RefreshRequest,
    RegisterRequest,
    ResetPasswordRequest,
    TokenResponse,
    UserOut,
    VerifyEmailRequest,
)
from app.services.audit import log_action
from app.services.email import send_password_reset_email, send_verification_email

router = APIRouter(prefix="/auth", tags=["Authentication"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_MINUTES = 15


def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _device_fingerprint(request: Request) -> str:
    ua = request.headers.get("user-agent", "unknown")
    accept_lang = request.headers.get("accept-language", "")
    return hashlib.sha256(f"{ua}|{accept_lang}".encode()).hexdigest()


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing:
        raise HTTPException(status_code=400, detail="An account with this email already exists")

    viewer_role = db.scalar(select(Role).where(Role.name == RoleName.VIEWER))
    if viewer_role is None:
        raise HTTPException(status_code=500, detail="Default roles are not seeded. Run the seed script first.")

    from app.config import settings

    user = User(
        full_name=payload.full_name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role_id=viewer_role.id,
        is_verified=not bool(settings.SMTP_HOST),
        verification_token=None if settings.SMTP_HOST else generate_random_token(16),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    if settings.SMTP_HOST:
        send_verification_email(user.email, user.full_name, user.verification_token)
    else:
        logger.info("DEV MODE: auto-verified user %s (no SMTP configured)", user.email)
    log_action(db, action="register", module="auth", user_id=user.id, ip_address=_client_ip(request))

    return UserOut(
        id=user.id, full_name=user.full_name, email=user.email,
        role=viewer_role.name, is_active=user.is_active, is_verified=user.is_verified,
        created_at=user.created_at,
    )


@router.post("/verify-email", response_model=MessageResponse)
def verify_email(payload: VerifyEmailRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.verification_token == payload.token))
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    user.is_verified = True
    user.verification_token = None
    db.commit()
    return MessageResponse(message="Email verified successfully. You can now log in.")


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    ip = _client_ip(request)
    user = db.scalar(select(User).where(User.email == payload.email))

    if not user:
        log_action(db, action="login", module="auth", ip_address=ip, result="failure",
                   details=f"Unknown email: {payload.email}")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if user.locked_until and user.locked_until > datetime.utcnow():
        raise HTTPException(
            status_code=423,
            detail=f"Account locked until {user.locked_until.isoformat()} due to repeated failed logins",
        )

    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.locked_until = datetime.utcnow() + timedelta(minutes=LOCKOUT_MINUTES)
        db.commit()
        log_action(db, action="login", module="auth", user_id=user.id, ip_address=ip, result="failure",
                   details="Incorrect password")
        raise HTTPException(status_code=401, detail="Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled. Contact an administrator.")

    if not user.is_verified:
        raise HTTPException(status_code=403, detail="Please verify your email before logging in")

    # --- Login anomaly detection: unknown device fingerprint ---
    fingerprint = _device_fingerprint(request)
    known_device = db.scalar(
        select(Device).where(Device.user_id == user.id, Device.device_fingerprint == fingerprint)
    )
    if known_device is None:
        db.add(Device(
            user_id=user.id, device_fingerprint=fingerprint,
            user_agent=request.headers.get("user-agent", ""), is_trusted=False,
        ))
        log_action(db, action="new_device_login", module="login_anomaly", user_id=user.id,
                   ip_address=ip, result="success", details="First login from this device/browser")
    else:
        known_device.last_seen = datetime.utcnow()

    # Reset failure counters, record success
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login_at = datetime.utcnow()
    user.last_login_ip = ip
    user.last_login_device = request.headers.get("user-agent", "")
    db.commit()

    access_token = create_access_token(str(user.id), extra_claims={"role": user.role.name})
    refresh_token = create_refresh_token(str(user.id))

    session = UserSession(
        user_id=user.id,
        refresh_token_hash=hash_token(refresh_token),
        ip_address=ip,
        device_fingerprint=fingerprint,
        user_agent=request.headers.get("user-agent", ""),
        expires_at=datetime.utcnow() + timedelta(days=7),
    )
    db.add(session)
    db.commit()

    log_action(db, action="login", module="auth", user_id=user.id, ip_address=ip, result="success")
    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


@router.post("/refresh", response_model=TokenResponse)
def refresh_token_endpoint(payload: RefreshRequest, db: Session = Depends(get_db)):
    try:
        claims = decode_token(payload.refresh_token)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    if claims.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid token type")

    token_hash = hash_token(payload.refresh_token)
    session = db.scalar(select(UserSession).where(UserSession.refresh_token_hash == token_hash))
    if session is None or session.is_revoked or session.expires_at < datetime.now(timezone.utc).replace(tzinfo=None):
        raise HTTPException(status_code=401, detail="Session expired or revoked. Please log in again.")

    user = db.get(User, session.user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="User no longer active")

    # Rotate refresh token
    session.is_revoked = True
    db.commit()

    new_access = create_access_token(str(user.id), extra_claims={"role": user.role.name})
    new_refresh = create_refresh_token(str(user.id))
    new_session = UserSession(
        user_id=user.id,
        refresh_token_hash=hash_token(new_refresh),
        ip_address=session.ip_address,
        device_fingerprint=session.device_fingerprint,
        user_agent=session.user_agent,
        expires_at=datetime.utcnow() + timedelta(days=7),
    )
    db.add(new_session)
    db.commit()

    return TokenResponse(access_token=new_access, refresh_token=new_refresh)


@router.post("/logout", response_model=MessageResponse)
def logout(payload: RefreshRequest, db: Session = Depends(get_db),
           current_user: User = Depends(get_current_active_user)):
    token_hash = hash_token(payload.refresh_token)
    session = db.scalar(select(UserSession).where(UserSession.refresh_token_hash == token_hash))
    if session:
        session.is_revoked = True
        db.commit()
    log_action(db, action="logout", module="auth", user_id=current_user.id)
    return MessageResponse(message="Logged out successfully")


@router.post("/forgot-password", response_model=MessageResponse)
def forgot_password(payload: ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.email == payload.email))
    # Always return the same message to avoid leaking which emails are registered
    generic_message = MessageResponse(message="If that email is registered, a reset link has been sent.")
    if not user:
        return generic_message

    user.reset_password_token = generate_random_token(16)
    user.reset_password_expires = datetime.utcnow() + timedelta(minutes=30)
    db.commit()

    send_password_reset_email(user.email, user.full_name, user.reset_password_token)
    return generic_message


@router.post("/reset-password", response_model=MessageResponse)
def reset_password(payload: ResetPasswordRequest, db: Session = Depends(get_db)):
    user = db.scalar(select(User).where(User.reset_password_token == payload.token))
    if not user or not user.reset_password_expires or user.reset_password_expires < datetime.utcnow():
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    user.hashed_password = hash_password(payload.new_password)
    user.reset_password_token = None
    user.reset_password_expires = None
    user.failed_login_attempts = 0
    user.locked_until = None
    db.commit()

    log_action(db, action="reset_password", module="auth", user_id=user.id)
    return MessageResponse(message="Password reset successfully. You can now log in with your new password.")


@router.get("/me", response_model=UserOut)
def get_me(current_user: User = Depends(get_current_active_user)):
    return UserOut(
        id=current_user.id, full_name=current_user.full_name, email=current_user.email,
        role=current_user.role.name, is_active=current_user.is_active,
        is_verified=current_user.is_verified, created_at=current_user.created_at,
    )
