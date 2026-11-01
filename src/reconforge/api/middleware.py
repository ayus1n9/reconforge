"""HTTP middleware for request timing and security limits."""

import logging
import time
from collections.abc import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

logger = logging.getLogger("reconforge.api.middleware")


class PayloadSizeLimitMiddleware(BaseHTTPMiddleware):
    """Enforce maximum incoming payload size to guard against memory exhaustion attacks."""

    def __init__(self, app, max_upload_size_bytes: int = 10 * 1024 * 1024):
        super().__init__(app)
        self.max_upload_size_bytes = max_upload_size_bytes

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_upload_size_bytes:
                    return JSONResponse(
                        status_code=413,
                        content={
                            "detail": (
                                f"Payload size {length} bytes exceeds maximum allowed "
                                f"limit of {self.max_upload_size_bytes} bytes."
                            )
                        },
                    )
            except ValueError:
                return JSONResponse(
                    status_code=400, content={"detail": "Invalid Content-Length header."}
                )
        return await call_next(request)


class RequestTimingMiddleware(BaseHTTPMiddleware):
    """Calculate request processing time and attach diagnostic telemetry headers."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        start_time = time.perf_counter()
        response = await call_next(request)
        process_time = time.perf_counter() - start_time
        response.headers["X-Process-Time"] = f"{process_time:.6f}"
        return response
