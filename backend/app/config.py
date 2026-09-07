from functools import lru_cache

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

SCAN_JOB_LEASE_SAFETY_MARGIN_SECONDS = 60


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, extra="ignore")

    app_env: str = "local"
    web_origin: str = "http://localhost:3000"
    database_url: str
    session_secret: str
    session_absolute_ttl_seconds: int = 3600
    invitation_ttl_seconds: int = 86_400
    smtp_host: str = "localhost"
    smtp_port: int = 1025
    mail_from: str = "no-reply@toy-sast.local"
    max_upload_bytes: int = 50 * 1024 * 1024
    max_request_body_bytes: int = 51 * 1024 * 1024
    max_archive_entries: int = 10_000
    max_extracted_bytes: int = 200 * 1024 * 1024
    source_storage_root: str = "/data/sources"
    workspace_root: str = "/work"
    analysis_timeout_seconds: int = Field(default=300, gt=0)
    analysis_idle_timeout_seconds: int = Field(default=180, gt=0)
    analysis_max_timeout_seconds: int = Field(default=1800, gt=0)
    analysis_heartbeat_seconds: int = Field(default=30, gt=0)
    analyzer_max_output_bytes: int = 16 * 1024 * 1024
    analyzer_max_findings: int = 10_000
    analyzer_rules_root: str = "/analyzer/rules"
    worker_poll_seconds: float = 1.0
    scan_job_lease_seconds: int = 600
    scan_max_attempts: int = 3

    @model_validator(mode="after")
    def validate_scan_job_lease(self) -> "Settings":
        """Validate adaptive analyzer timing and reserve finalization time."""
        if self.analysis_max_timeout_seconds < self.analysis_timeout_seconds:
            raise ValueError(
                "analysis_max_timeout_seconds must be at least analysis_timeout_seconds"
            )
        if self.analysis_idle_timeout_seconds < self.analysis_heartbeat_seconds * 2:
            raise ValueError(
                "analysis_idle_timeout_seconds must be at least twice analysis_heartbeat_seconds"
            )
        if self.scan_job_lease_seconds < self.analysis_heartbeat_seconds * 2:
            raise ValueError(
                "scan_job_lease_seconds must be at least twice analysis_heartbeat_seconds"
            )
        minimum_lease_seconds = self.analysis_timeout_seconds + SCAN_JOB_LEASE_SAFETY_MARGIN_SECONDS
        if self.scan_job_lease_seconds < minimum_lease_seconds:
            raise ValueError(
                "scan_job_lease_seconds must be at least analysis_timeout_seconds + "
                f"{SCAN_JOB_LEASE_SAFETY_MARGIN_SECONDS}"
            )
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings(**{})  # BaseSettings loads required values from env.
