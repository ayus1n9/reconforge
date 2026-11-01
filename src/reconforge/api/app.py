"""FastAPI application factory, lifespan management, middleware, and route registration."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from reconforge import __version__
from reconforge.api.config import APISettings
from reconforge.api.manager import ScanExecutionManager
from reconforge.api.middleware import PayloadSizeLimitMiddleware, RequestTimingMiddleware
from reconforge.api.routes import (
    assessments,
    assets,
    diff,
    findings,
    reports,
    scope,
    scoring,
    snapshots,
    system,
)
from reconforge.core.exceptions import ConfigurationError, ScopeViolationError
from reconforge.storage.database import DatabaseManager

logger = logging.getLogger("reconforge.api")


def create_app(settings: APISettings | None = None) -> FastAPI:
    """Create and configure a production-hardened FastAPI application instance."""
    app_settings = settings or APISettings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
        # Startup
        logger.info("Initializing ReconForge Security Intelligence API (v%s)", __version__)
        db = DatabaseManager(db_url=app_settings.db_url)
        db.init_db()
        app.state.db = db
        app.state.settings = app_settings
        app.state.scan_manager = ScanExecutionManager()

        if app_settings.api_key:
            logger.info("API Key authentication is ACTIVE.")
        else:
            logger.warning(
                "API Key authentication is DISABLED (local-first mode). "
                "Ensure API is bound only to 127.0.0.1."
            )

        yield

        # Shutdown
        logger.info("Shutting down ReconForge API; cancelling running background scans...")
        await app.state.scan_manager.cancel_all(db)
        logger.info("ReconForge API shutdown complete.")

    app = FastAPI(
        title=app_settings.title,
        version=app_settings.version,
        description=(
            "Intelligent Network Attack-Surface Mapping, Exposure Assessment "
            "& Security Intelligence RESTful API."
        ),
        docs_url=app_settings.docs_url,
        redoc_url=app_settings.redoc_url,
        lifespan=lifespan,
    )

    # Middleware registration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=app_settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.add_middleware(
        PayloadSizeLimitMiddleware,
        max_upload_size_bytes=app_settings.max_upload_size_bytes,
    )
    app.add_middleware(RequestTimingMiddleware)

    # Global Exception Handlers
    @app.exception_handler(ScopeViolationError)
    async def scope_violation_handler(request: Request, exc: ScopeViolationError):
        logger.warning("Scope violation on %s: %s", request.url.path, exc)
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={"detail": f"Scope Authorization Violation: {exc}"},
        )

    @app.exception_handler(ConfigurationError)
    async def configuration_error_handler(request: Request, exc: ConfigurationError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": f"Configuration Error: {exc}"},
        )

    @app.exception_handler(ValueError)
    async def value_error_handler(request: Request, exc: ValueError):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": str(exc)},
        )

    # Root endpoint
    @app.get("/", tags=["Root"], summary="API Root & Navigation")
    async def root():
        return {
            "name": app_settings.title,
            "version": app_settings.version,
            "docs": app_settings.docs_url,
            "redoc": app_settings.redoc_url,
            "health": "/api/v1/health",
            "system": "/api/v1/system",
        }

    # Mount v1 routers under /api/v1
    from fastapi import APIRouter

    v1_router = APIRouter(prefix="/api/v1")
    v1_router.include_router(system.router)
    v1_router.include_router(scope.router)
    v1_router.include_router(assessments.router)
    v1_router.include_router(assets.router)
    v1_router.include_router(findings.router)
    v1_router.include_router(scoring.router)
    v1_router.include_router(diff.router)
    v1_router.include_router(reports.router)
    v1_router.include_router(snapshots.router)

    app.include_router(v1_router)

    return app


# Default application instance for ASGI servers
app = create_app()
