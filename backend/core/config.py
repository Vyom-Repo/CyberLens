from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    """Application and environment configuration settings."""
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    # API Keys
    vt_api_key: str = Field(default="", alias="VT_API_KEY")
    abuseipdb_api_key: str = Field(default="", alias="ABUSEIPDB_API_KEY")

    # Mode: false = live external APIs, true = offline simulation
    offline_mode: bool = Field(default=False, alias="OFFLINE_MODE")

    # Database
    database_url: str = Field(
        default="sqlite:///./analysis_history.db",
        alias="DATABASE_URL"
    )

    # Server & Security
    host: str = Field(default="127.0.0.1", alias="HOST")
    port: int = Field(default=8000, alias="PORT")
    cors_origins: List[str] = Field(
        default=["http://localhost:8000", "http://127.0.0.1:8000"],
        alias="CORS_ORIGINS"
    )


settings = Settings()
