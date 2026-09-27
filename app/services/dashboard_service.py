from datetime import datetime, timedelta, timezone

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.vulnerability import ReviewStatus, Severity, Status, Vulnerability


async def get_dashboard_stats(db: AsyncSession, current_user: User) -> dict:
    client_roles = ("manager", "developer", "viewer")
    review_filter = (
        Vulnerability.review_status == ReviewStatus.approved
        if current_user.role in client_roles
        else None
    )

    def _base():
        cond = Vulnerability.deleted_at.is_(None)
        if review_filter is not None:
            return cond & review_filter
        return cond

    base = _base()

    # by_severity
    rows = await db.execute(
        select(Vulnerability.severity, func.count())
        .where(base)
        .group_by(Vulnerability.severity)
    )
    by_severity = {c.value: 0 for c in Severity}
    for severity, count in rows:
        by_severity[severity.value] = count

    # by_status
    rows = await db.execute(
        select(Vulnerability.status, func.count())
        .where(base)
        .group_by(Vulnerability.status)
    )
    by_status = {s.value: 0 for s in Status}
    for status, count in rows:
        by_status[status.value] = count

    # weekly_trend — last 12 weeks
    twelve_weeks_ago = datetime.now(timezone.utc) - timedelta(weeks=12)
    rows = await db.execute(
        select(
            func.date_trunc("week", Vulnerability.created_at).label("week"),
            func.count().label("created"),
            func.sum(
                case((Vulnerability.status == Status.closed, 1), else_=0)
            ).label("closed"),
        )
        .where(base, Vulnerability.created_at >= twelve_weeks_ago)
        .group_by("week")
        .order_by("week")
    )
    weekly_trend = [
        {"week": row.week.strftime("%Y-%m-%d"), "created": row.created, "closed": row.closed}
        for row in rows
    ]

    # top_targets — top 10 by vuln count, with worst severity
    severity_rank = case(
        (Vulnerability.severity == Severity.critical, 4),
        (Vulnerability.severity == Severity.high, 3),
        (Vulnerability.severity == Severity.medium, 2),
        else_=1,
    )
    rank_to_sev = {4: "critical", 3: "high", 2: "medium", 1: "low"}
    rows = await db.execute(
        select(
            Vulnerability.target,
            func.count().label("count"),
            func.max(severity_rank).label("worst_rank"),
        )
        .where(base)
        .group_by(Vulnerability.target)
        .order_by(func.count().desc())
        .limit(10)
    )
    top_targets = [
        {
            "target": row.target,
            "count": row.count,
            "worst_severity": rank_to_sev[row.worst_rank],
        }
        for row in rows
    ]

    return {
        "by_severity": by_severity,
        "by_status": by_status,
        "weekly_trend": weekly_trend,
        "top_targets": top_targets,
    }
