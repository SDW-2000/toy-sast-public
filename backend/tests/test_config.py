import pytest
from pydantic import ValidationError

from app.config import SCAN_JOB_LEASE_SAFETY_MARGIN_SECONDS, Settings


def test_default_settings_reserve_worker_cleanup_margin() -> None:
    settings = Settings()

    assert settings.analysis_timeout_seconds == 300
    assert settings.analysis_idle_timeout_seconds == 180
    assert settings.analysis_max_timeout_seconds == 1800
    assert settings.analysis_heartbeat_seconds == 30
    assert settings.scan_job_lease_seconds >= (
        settings.analysis_timeout_seconds + SCAN_JOB_LEASE_SAFETY_MARGIN_SECONDS
    )


def test_settings_reject_lease_without_worker_cleanup_margin() -> None:
    with pytest.raises(ValidationError, match="scan_job_lease_seconds"):
        Settings(
            analysis_timeout_seconds=300,
            scan_job_lease_seconds=300 + SCAN_JOB_LEASE_SAFETY_MARGIN_SECONDS - 1,
        )


def test_settings_reject_invalid_adaptive_analysis_timing() -> None:
    with pytest.raises(ValidationError, match="analysis_max_timeout_seconds"):
        Settings(analysis_timeout_seconds=300, analysis_max_timeout_seconds=299)
    with pytest.raises(ValidationError, match="analysis_idle_timeout_seconds"):
        Settings(analysis_idle_timeout_seconds=59, analysis_heartbeat_seconds=30)
    with pytest.raises(ValidationError, match="scan_job_lease_seconds"):
        Settings(
            analysis_timeout_seconds=1,
            analysis_idle_timeout_seconds=200,
            analysis_heartbeat_seconds=100,
            scan_job_lease_seconds=199,
        )
