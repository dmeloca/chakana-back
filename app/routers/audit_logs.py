from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_db, require_roles
from app.schemas.audit_log import AuditLogListResponse
from app.services.audit_service import list_audit_logs

router = APIRouter(prefix="/audit-logs", tags=["audit-logs"])


@router.get("/", response_model=AuditLogListResponse)
async def get_audit_logs(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = require_roles("admin"),
):
    items, total = await list_audit_logs(db, skip, limit)
    return AuditLogListResponse(items=items, total=total, skip=skip, limit=limit)
