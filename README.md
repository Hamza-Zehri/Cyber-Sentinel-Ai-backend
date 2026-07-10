# Cyber Sentinel AI — Backend API

Enterprise-grade cybersecurity platform REST API built with FastAPI.

## Features

- **Authentication & RBAC** — JWT access/refresh tokens, email verification, forgot/reset password, account lockout, role-based access control (Admin / Security Analyst / Viewer)
- **Network Monitor** — Live packet capture via Scapy + Npcap, 16 attack-type IDS engine, paginated/filterable packet views
- **AI Security Modules** — Phishing URL detector (RandomForest), Malware file scanner (entropy + RandomForest), Password strength analyzer
- **Admin Panel** — User management, role/permission viewer, audit log browser
- **Reports** — Generate CSV reports (alerts, network traffic, AI scans)
- **Settings** — System-wide key-value configuration
- **Backups** — SQLite database backup, download, and restore
- **Notifications** — In-app notification system with unread counts

## Quick Start

```bash
pip install -r requirements.txt
cp ../.env.example .env   # edit as needed
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

- API docs: http://localhost:8000/api/docs
- Default admin: `admin@cybersentinel.ai` / `ChangeMe123!`

## Requirements

- **Python 3.10+**
- **Redis** (for rate limiting, optional in dev)
- **Npcap** with WinPcap API mode (Windows only, for packet capture — install as Administrator)

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./cybersentinel_dev.db` | PostgreSQL or SQLite URL |
| `JWT_SECRET_KEY` | `CHANGE_ME` | Secret for JWT signing |
| `SMTP_HOST` | _(empty)_ | SMTP host for emails (empty = dev mode auto-verify) |
| `CORS_ORIGINS` | `http://localhost:5173` | Comma-separated allowed origins |
| `RATE_LIMIT_PER_MINUTE` | `60` | API rate limit |

## API Endpoints (29 total)

### Authentication (`/api/v1/auth`)
`POST register` · `POST verify-email` · `POST login` · `POST refresh` · `POST logout` · `POST forgot-password` · `POST reset-password` · `GET me`

### Network Monitor (`/api/v1/network`)
`GET interfaces` · `POST capture/start` · `POST capture/stop` · `GET capture/status` · `GET packets` · `DELETE packets` · `GET resolve?ip=`

### Alerts (`/api/v1/alerts`)
`GET alerts` · `POST alerts/{id}/resolve`

### AI Security (`/api/v1/ai`)
`POST phishing/check` · `POST malware/scan` · `POST password/analyze`

### Admin (`/api/v1/admin`)
`GET users` · `GET/PATCH users/{id}` · `GET roles` · `POST roles` · `PATCH roles/{id}` · `GET audit-logs`

### Reports (`/api/v1/reports`)
`POST generate` · `GET reports` · `GET download/{id}`

### Settings (`/api/v1/settings`)
`GET settings` · `POST settings` · `PATCH settings/{id}`

### Backups (`/api/v1/backups`)
`POST create` · `GET backups` · `GET download/{filename}` · `POST restore/{filename}`

### Notifications (`/api/v1/notifications`)
`GET notifications` · `GET unread-count` · `POST {id}/read` · `POST mark-all-read`

## Testing

```bash
cd backend
pip install -r requirements.txt
pytest tests/ -v
```

## Frontend

The React dashboard is at [Cyber-Sentinel-Ai-frontend](https://github.com/Hamza-Zehri/Cyber-Sentinel-Ai-frontend).

## License

MIT
