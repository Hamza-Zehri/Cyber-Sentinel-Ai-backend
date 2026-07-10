"""
Cyber Sentinel AI - Authentication test suite.
Covers registration, email verification, login, JWT issuance, refresh-token
rotation, account lockout, forgot/reset password, and logout.
"""
from sqlalchemy import select


def _get_user_token_fields(email: str):
    from app.database import SessionLocal
    from app.models.user import User

    db = SessionLocal()
    try:
        user = db.scalar(select(User).where(User.email == email))
        return user.verification_token, user.reset_password_token
    finally:
        db.close()


def test_register_creates_unverified_viewer(client):
    r = client.post("/api/v1/auth/register", json={
        "full_name": "Jane Analyst", "email": "jane@example.com", "password": "SecurePass1!",
    })
    assert r.status_code == 201
    body = r.json()
    assert body["role"] == "viewer"
    assert body["is_verified"] is False


def test_register_rejects_duplicate_email(client):
    payload = {"full_name": "Jane", "email": "dup@example.com", "password": "SecurePass1!"}
    assert client.post("/api/v1/auth/register", json=payload).status_code == 201
    r2 = client.post("/api/v1/auth/register", json=payload)
    assert r2.status_code == 400


def test_register_rejects_weak_password(client):
    r = client.post("/api/v1/auth/register", json={
        "full_name": "Jane", "email": "weak@example.com", "password": "weakpass",
    })
    assert r.status_code == 422


def test_login_blocked_until_email_verified(client):
    client.post("/api/v1/auth/register", json={
        "full_name": "Jane", "email": "jane2@example.com", "password": "SecurePass1!",
    })
    r = client.post("/api/v1/auth/login", json={"email": "jane2@example.com", "password": "SecurePass1!"})
    assert r.status_code == 403


def test_full_login_flow_after_verification(client):
    client.post("/api/v1/auth/register", json={
        "full_name": "Jane", "email": "jane3@example.com", "password": "SecurePass1!",
    })
    token, _ = _get_user_token_fields("jane3@example.com")
    assert client.post("/api/v1/auth/verify-email", json={"token": token}).status_code == 200

    r = client.post("/api/v1/auth/login", json={"email": "jane3@example.com", "password": "SecurePass1!"})
    assert r.status_code == 200
    tokens = r.json()
    assert "access_token" in tokens and "refresh_token" in tokens

    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200
    assert me.json()["email"] == "jane3@example.com"


def test_account_locks_after_max_failed_attempts(client):
    client.post("/api/v1/auth/register", json={
        "full_name": "Jane", "email": "jane4@example.com", "password": "SecurePass1!",
    })
    token, _ = _get_user_token_fields("jane4@example.com")
    client.post("/api/v1/auth/verify-email", json={"token": token})

    for _ in range(5):
        client.post("/api/v1/auth/login", json={"email": "jane4@example.com", "password": "wrong"})

    r = client.post("/api/v1/auth/login", json={"email": "jane4@example.com", "password": "SecurePass1!"})
    assert r.status_code == 423


def test_refresh_token_rotation_and_reuse_rejection(client):
    r = client.post("/api/v1/auth/login", json={"email": "admin@cybersentinel.ai", "password": "AdminPass123!"})
    assert r.status_code == 200
    old_tokens = r.json()

    r2 = client.post("/api/v1/auth/refresh", json={"refresh_token": old_tokens["refresh_token"]})
    assert r2.status_code == 200

    # Reusing the rotated-out refresh token must fail
    r3 = client.post("/api/v1/auth/refresh", json={"refresh_token": old_tokens["refresh_token"]})
    assert r3.status_code == 401


def test_forgot_and_reset_password_flow(client):
    client.post("/api/v1/auth/register", json={
        "full_name": "Jane", "email": "jane5@example.com", "password": "SecurePass1!",
    })
    v_token, _ = _get_user_token_fields("jane5@example.com")
    client.post("/api/v1/auth/verify-email", json={"token": v_token})

    r = client.post("/api/v1/auth/forgot-password", json={"email": "jane5@example.com"})
    assert r.status_code == 200

    _, reset_token = _get_user_token_fields("jane5@example.com")
    r2 = client.post("/api/v1/auth/reset-password", json={"token": reset_token, "new_password": "NewSecure2!"})
    assert r2.status_code == 200

    r3 = client.post("/api/v1/auth/login", json={"email": "jane5@example.com", "password": "NewSecure2!"})
    assert r3.status_code == 200


def test_forgot_password_does_not_leak_unknown_emails(client):
    r = client.post("/api/v1/auth/forgot-password", json={"email": "nobody@example.com"})
    assert r.status_code == 200
    assert "registered" in r.json()["message"]


def test_logout_revokes_session(client):
    r = client.post("/api/v1/auth/login", json={"email": "admin@cybersentinel.ai", "password": "AdminPass123!"})
    tokens = r.json()
    r2 = client.post(
        "/api/v1/auth/logout",
        json={"refresh_token": tokens["refresh_token"]},
        headers={"Authorization": f"Bearer {tokens['access_token']}"},
    )
    assert r2.status_code == 200

    # The revoked refresh token can no longer be used to get new tokens
    r3 = client.post("/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert r3.status_code == 401


def test_admin_bootstrap_user_has_admin_role(client):
    r = client.post("/api/v1/auth/login", json={"email": "admin@cybersentinel.ai", "password": "AdminPass123!"})
    assert r.status_code == 200
    me = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {r.json()['access_token']}"})
    assert me.json()["role"] == "admin"
