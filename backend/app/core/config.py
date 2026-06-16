from pydantic_settings import BaseSettings
from typing import List
import os


class Settings(BaseSettings):
    # App
    APP_NAME: str = "NetScan AI"
    DEBUG: bool = False
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-super-secret-key-change-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 1440  # 24 hours

    # Database
    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "postgresql+asyncpg://netscan:netscan_pass@localhost:5432/netscan_db"
    )

    # CORS
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
    ]

    # Scanner
    DEFAULT_SCAN_TIMEOUT: int = 3
    MAX_CONCURRENT_SCANS: int = 100
    MAX_PORTS_PER_SCAN: int = 65535

    # ML Model
    MODEL_PATH: str = "./ml_models/"
    RISK_THRESHOLD_HIGH: float = 0.7
    RISK_THRESHOLD_MEDIUM: float = 0.4

    # Email Alert Settings
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.gmail.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "465"))
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    ENABLE_EMAIL_ALERTS: bool = os.getenv("ENABLE_EMAIL_ALERTS", "false").lower() == "true"

    class Config:
        env_file = ".env"


settings = Settings()