"""
Cyber Sentinel AI - Application Configuration
Loads settings from environment variables / .env file.
"""
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # --- App ---
    APP_NAME: str = "Cyber Sentinel AI"
    APP_ENV: str = "development"
    DEBUG: bool = True
    API_V1_PREFIX: str = "/api/v1"

    # --- Database ---
    DATABASE_URL: str = "sqlite:///./cybersentinel_dev.db"
    POSTGRES_USER: str = "cybersentinel"
    POSTGRES_PASSWORD: str = "cybersentinel_pass"
    POSTGRES_DB: str = "cybersentinel_db"
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432

    # --- Redis / Celery ---
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0

    @property
    def REDIS_URL(self) -> str:
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"

    CELERY_BROKER_URL: str = ""
    CELERY_RESULT_BACKEND: str = ""

    # --- Security / JWT ---
    JWT_SECRET_KEY: str = "CHANGE_THIS_SECRET_IN_PRODUCTION_ENV_FILE"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # --- CORS ---
    CORS_ORIGINS: str = "http://localhost:5173,http://localhost:3000"

    # --- Email / SMTP ---
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = "noreply@cybersentinel.ai"

    # --- Rate limiting ---
    RATE_LIMIT_PER_MINUTE: int = 60

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


@lru_cache
def get_settings() -> Settings:
    settings = Settings()
    if not settings.CELERY_BROKER_URL:
        settings.CELERY_BROKER_URL = settings.REDIS_URL
    if not settings.CELERY_RESULT_BACKEND:
        settings.CELERY_RESULT_BACKEND = settings.REDIS_URL
    return settings


settings = get_settings()
