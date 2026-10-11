"""Application settings. Values come from VDM_* environment variables or a .env file.
Credentials belong in the environment or secret store, never in this file."""

from __future__ import annotations

from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VDM_", env_file=".env", env_file_encoding="utf-8", extra="ignore")

    database_url: str = Field("sqlite:///./data/vdm.db", description="SQLAlchemy URL; PostgreSQL for shared use")
    max_upload_mb: int = Field(50, ge=1, le=2048)
    max_inventory_rows: int = Field(20_000, ge=1)
    default_actor: str = Field("local-user", description="Audit actor until authentication exists (Phase 2)")
    criticality_values: list[str] = Field(default_factory=lambda: ["critical", "high", "medium", "low"])

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
