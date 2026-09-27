from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.config import settings
from app.limiter import limiter
from app.middleware.audit_log import AuditLogMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.routers import auth, dashboard, vulns
from app.routers import comments, audit_logs, users

app = FastAPI(title="secure_flow")

# Middleware order: security headers → audit log → CORS → slowapi
app.add_middleware(SlowAPIMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=[str(o) for o in settings.ALLOWED_ORIGINS],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["Authorization", "Content-Type"],
)
app.add_middleware(AuditLogMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.include_router(auth.router)
app.include_router(vulns.router)
app.include_router(comments.router)
app.include_router(dashboard.router)
app.include_router(audit_logs.router)
app.include_router(users.router)


@app.get("/health")
async def health():
    return {"status": "ok"}
