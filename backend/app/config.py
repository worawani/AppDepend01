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

    # Import validation policy (decision 3). Per request, partial import is always opt-in and needs a
    # written reason; this switch lets an administrator disable partial imports altogether.
    allow_partial_imports: bool = True
    partial_reason_min_length: int = Field(10, ge=1, le=500)
    max_invalid_record_ratio: float = Field(0.5, gt=0, le=1, description="above this, the file is rejected as unparseable")
    max_rejected_rows_stored: int = Field(100_000, ge=100)
    issue_examples_per_code: int = Field(100, ge=1)

    # Telemetry. Measured: ~0.6 KB RAM per distinct (hour, src, dst, protocol, port) during import, so the
    # worst case at 2M records (no repetition at all) is ~1.2 GB. Split larger exports per day.
    max_telemetry_upload_mb: int = Field(512, ge=1, le=10_240)
    max_telemetry_rows: int = Field(2_000_000, ge=1)

    # Endpoint resolution: an inventory IP observed more than this many days from the inventory
    # snapshot may have been re-assigned, so the mapping confidence drops to medium.
    inventory_staleness_days: int = Field(90, ge=1)

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * 1024 * 1024

    @property
    def max_telemetry_bytes(self) -> int:
        return self.max_telemetry_upload_mb * 1024 * 1024


@lru_cache
def get_settings() -> Settings:
    return Settings()
