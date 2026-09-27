import logging
from time import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

logger = logging.getLogger("audit")

MUTATING_METHODS = {"POST", "PUT", "DELETE", "PATCH"}


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        start_time = time()

        response = await call_next(request)

        if request.method not in MUTATING_METHODS and not request.url.path.startswith("/auth/"):
            return response

        user = getattr(request.state, "user", None)

        # TODO (Phase 1): replace logger with DB write to audit_logs table once AuditLog model exists
        logger.info(
            "audit_event",
            extra={
                "user_id": getattr(user, "id", None),
                "method": request.method,
                "path": request.url.path,
                "status_code": response.status_code,
                "client_ip": request.client.host if request.client else None,
                "user_agent": request.headers.get("user-agent"),
                "duration_ms": round((time() - start_time) * 1000, 2),
            },
        )

        return response
