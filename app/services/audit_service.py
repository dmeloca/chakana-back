from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.audit_log import AuditLog


async def list_audit_logs(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
) -> tuple[list[AuditLog], int]:
    total = await db.scalar(select(func.count()).select_from(AuditLog))
    rows = await db.execute(
        select(AuditLog).order_by(AuditLog.timestamp.desc()).offset(skip).limit(limit)
    )
    return list(rows.scalars().all()), total or 0
