"""API configuration and settings for ReconForge."""

import os
from dataclasses import dataclass, field


@dataclass
class APISettings:
    """Configuration options for the ReconForge FastAPI service."""

    host: str = "127.0.0.1"
    port: int = 8000
    api_key: str | None = None
    cors_origins: list[str] = field(
        default_factory=lambda: [
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:5173",
            "http://127.0.0.1:5173",
        ]
    )
    max_upload_size_bytes: int = 10 * 1024 * 1024  # 10 MB limit
    db_url: str | None = None
    title: str = "ReconForge Security Intelligence API"
    version: str = "0.8.0"
    docs_url: str = "/docs"
    redoc_url: str = "/redoc"

    @classmethod
    def from_env(cls) -> "APISettings":
        """Load API settings from environment variables."""
        origins_env = os.getenv("RECONFORGE_CORS_ORIGINS")
        origins = (
            [o.strip() for o in origins_env.split(",") if o.strip()]
            if origins_env
            else [
                "http://localhost:3000",
                "http://127.0.0.1:3000",
                "http://localhost:5173",
                "http://127.0.0.1:5173",
            ]
        )
        return cls(
            host=os.getenv("RECONFORGE_API_HOST", "127.0.0.1"),
            port=int(os.getenv("RECONFORGE_API_PORT", "8000")),
            api_key=os.getenv("RECONFORGE_API_KEY"),
            cors_origins=origins,
            db_url=os.getenv("RECONFORGE_DB_URL"),
        )
