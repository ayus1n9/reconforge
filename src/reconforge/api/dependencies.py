"""Dependency injection providers for database, repositories, security, and engines."""

import secrets

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from reconforge.assessment.engine import ExposureEngine
from reconforge.diffing.engine import AssessmentDifferencer
from reconforge.intelligence.cache import VulnerabilityCache
from reconforge.intelligence.correlator import VulnerabilityCorrelator
from reconforge.inventory.repository import AssetRepository
from reconforge.inventory.snapshot import SnapshotManager
from reconforge.reporting.engine import ReportEngine
from reconforge.scoring.calculator import AttackSurfaceCalculator
from reconforge.storage.database import DatabaseManager

api_key_header_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)


def get_db(request: Request) -> DatabaseManager:
    """Provide the application-scoped DatabaseManager instance."""
    if hasattr(request.app.state, "db") and request.app.state.db is not None:
        return request.app.state.db
    db = DatabaseManager()
    db.init_db()
    return db


def get_repository(db: DatabaseManager = Depends(get_db)) -> AssetRepository:
    """Provide initialized AssetRepository."""
    return AssetRepository(db)


def get_exposure_engine() -> ExposureEngine:
    """Provide initialized ExposureEngine."""
    return ExposureEngine()


def get_cve_correlator(db: DatabaseManager = Depends(get_db)) -> VulnerabilityCorrelator:
    """Provide VulnerabilityCorrelator with initialized local CVE cache."""
    return VulnerabilityCorrelator(cache=VulnerabilityCache(db))


def get_scoring_calculator() -> AttackSurfaceCalculator:
    """Provide initialized AttackSurfaceCalculator."""
    return AttackSurfaceCalculator()


def get_differencer() -> AssessmentDifferencer:
    """Provide initialized AssessmentDifferencer."""
    return AssessmentDifferencer()


def get_report_engine() -> ReportEngine:
    """Provide initialized ReportEngine."""
    return ReportEngine()


def get_snapshot_manager(db: DatabaseManager = Depends(get_db)) -> SnapshotManager:
    """Provide initialized SnapshotManager."""
    return SnapshotManager(db)


async def verify_api_key(
    request: Request,
    api_key_header: str | None = Security(api_key_header_scheme),
    bearer_auth: HTTPAuthorizationCredentials | None = Security(bearer_scheme),
) -> str | None:
    """Enforce API key authentication if configured on the server.

    Employs constant-time string comparison to prevent timing side-channel attacks.
    """
    settings = getattr(request.app.state, "settings", None)
    expected_key = getattr(settings, "api_key", None) if settings else None

    # If no API key is configured on server, authentication is bypassed (local-first design)
    if not expected_key:
        return None

    provided_token: str | None = None
    if api_key_header:
        provided_token = api_key_header.strip()
    elif bearer_auth and bearer_auth.credentials:
        provided_token = bearer_auth.credentials.strip()

    if not provided_token or not secrets.compare_digest(provided_token, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return provided_token
