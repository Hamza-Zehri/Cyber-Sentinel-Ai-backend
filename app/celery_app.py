"""
Cyber Sentinel AI - Celery application.
Background tasks (report generation, scheduled backups, retention cleanup,
threat-intel refresh) are registered here as they are implemented stage by
stage. A working health-check task is included so the worker is verifiably
functional from the very first deployment.
"""
from celery import Celery

from app.config import settings

celery_app = Celery(
    "cybersentinel",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
)


@celery_app.task(name="cybersentinel.health_check")
def health_check_task() -> dict:
    """Simple task used to verify the Celery worker + broker are wired correctly."""
    return {"status": "ok", "worker": "cybersentinel-celery"}
