import csv
import io
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.vuln_history import VulnHistory
from app.models.vulnerability import ReviewStatus, Severity, Status, Vulnerability
from app.schemas.vulnerability import ReviewAction, VulnerabilityCreate, VulnerabilityUpdate

# Fields recorded in the change log (excludes large text blobs)
_TRACKED = {
    "status", "severity", "title", "assigned_to",
    "due_date", "cve_id", "cvss_score", "cvss_vector", "cwe_id",
    "review_status",
}


def _serialize(v: object) -> str | None:
    if v is None:
        return None
    if hasattr(v, "value"):          # Enum
        return v.value
    if isinstance(v, uuid.UUID):
        return str(v)
    if isinstance(v, datetime):
        return v.isoformat()
    return str(v)


def _clean(value: str) -> str:
    if "\x00" in value:
        raise ValueError("null bytes are not allowed")
    return value.strip()


async def _assert_assignee_not_admin(db: AsyncSession, assigned_to: uuid.UUID | None) -> None:
    if assigned_to is None:
        return
    result = await db.execute(select(User).where(User.id == assigned_to))
    user = result.scalar_one_or_none()
    if user and user.role == "admin":
        raise HTTPException(status_code=422, detail="Vulnerabilities cannot be assigned to an admin user")


def _visibility_filter(query, current_user: User):
    """Apply role-based review_status visibility gate to a query."""
    role = current_user.role
    if role in ("manager", "developer", "viewer"):
        return query.where(Vulnerability.review_status == ReviewStatus.approved)
    if role == "pentester":
        return query.where(
            or_(
                Vulnerability.review_status == ReviewStatus.approved,
                Vulnerability.created_by == current_user.id,
            )
        )
    # admin and reviewer: no filter — see everything
    return query


async def list_vulns(
    db: AsyncSession,
    current_user: User,
    status: Status | None = None,
    review_status: ReviewStatus | None = None,
    severity: Severity | None = None,
    target: str | None = None,
    search: str | None = None,
    assigned_to: uuid.UUID | None = None,
    skip: int = 0,
    limit: int = 25,
) -> tuple[list[Vulnerability], int]:
    base = select(Vulnerability).where(Vulnerability.deleted_at.is_(None))
    base = _visibility_filter(base, current_user)

    if status:
        base = base.where(Vulnerability.status == status)
    if review_status:
        base = base.where(Vulnerability.review_status == review_status)
    if severity:
        base = base.where(Vulnerability.severity == severity)
    if target:
        base = base.where(Vulnerability.target.ilike(f"%{target}%"))
    if search:
        base = base.where(
            or_(
                Vulnerability.title.ilike(f"%{search}%"),
                Vulnerability.description.ilike(f"%{search}%"),
            )
        )
    if assigned_to:
        base = base.where(Vulnerability.assigned_to == assigned_to)

    total = await db.scalar(select(func.count()).select_from(base.subquery()))
    stmt = base.order_by(Vulnerability.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(stmt)
    return list(result.scalars().all()), total or 0


async def get_vuln(
    db: AsyncSession,
    vuln_id: uuid.UUID,
    current_user: User | None = None,
) -> Vulnerability | None:
    base = select(Vulnerability).where(
        Vulnerability.id == vuln_id,
        Vulnerability.deleted_at.is_(None),
    )
    if current_user is not None:
        base = _visibility_filter(base, current_user)
    result = await db.execute(base)
    return result.scalar_one_or_none()


async def create_vuln(
    db: AsyncSession,
    data: VulnerabilityCreate,
    created_by: uuid.UUID,
    creator_role: str,
) -> Vulnerability:
    await _assert_assignee_not_admin(db, data.assigned_to)
    review_status = (
        ReviewStatus.approved if creator_role == "admin" else ReviewStatus.pending
    )
    vuln = Vulnerability(
        **data.model_dump(),
        created_by=created_by,
        review_status=review_status,
    )
    db.add(vuln)
    await db.commit()
    await db.refresh(vuln)
    return vuln


async def update_vuln(
    db: AsyncSession,
    vuln_id: uuid.UUID,
    data: VulnerabilityUpdate,
    current_user: User | None = None,
) -> Vulnerability | None:
    vuln = await get_vuln(db, vuln_id, current_user)
    if vuln is None:
        return None

    before = {f: _serialize(getattr(vuln, f)) for f in _TRACKED}

    updates = data.model_dump(exclude_unset=True)
    if "assigned_to" in updates:
        await _assert_assignee_not_admin(db, updates["assigned_to"])

    if current_user is None or current_user.role in ("admin", "reviewer"):
        for field, value in updates.items():
            setattr(vuln, field, value)
    elif current_user.role == "manager":
        if "assigned_to" in updates:
            vuln.assigned_to = updates["assigned_to"]
    elif current_user.role == "pentester":
        if vuln.created_by != current_user.id:
            raise HTTPException(status_code=403, detail="Can only edit your own vulnerabilities")
        for field, value in data.model_dump(exclude_unset=True).items():
            if field != "assigned_to":
                setattr(vuln, field, value)
        # Re-submit flow: editing a rejected vuln resets it to pending review
        if vuln.review_status == ReviewStatus.rejected:
            vuln.review_status = ReviewStatus.pending
    elif current_user.role == "developer":
        if vuln.assigned_to != current_user.id:
            raise HTTPException(status_code=403, detail="Can only update status of assigned vulnerabilities")
        if data.status is not None:
            vuln.status = data.status
    else:
        raise HTTPException(status_code=403, detail="Insufficient permissions")

    after = {f: _serialize(getattr(vuln, f)) for f in _TRACKED}
    changes = {
        f: {"from": before[f], "to": after[f]}
        for f in _TRACKED
        if before[f] != after[f]
    }
    if changes:
        db.add(VulnHistory(
            vuln_id=vuln_id,
            user_id=current_user.id if current_user else None,
            username=current_user.username if current_user else None,
            changes=changes,
        ))

    await db.commit()
    await db.refresh(vuln)
    return vuln


async def review_vuln(
    db: AsyncSession,
    vuln_id: uuid.UUID,
    action: ReviewAction,
    reviewer: User,
) -> Vulnerability | None:
    # Reviewer sees all vulns — no visibility gate here
    result = await db.execute(
        select(Vulnerability).where(
            Vulnerability.id == vuln_id,
            Vulnerability.deleted_at.is_(None),
        )
    )
    vuln = result.scalar_one_or_none()
    if vuln is None:
        return None

    before = {f: _serialize(getattr(vuln, f)) for f in _TRACKED}

    vuln.review_status = (
        ReviewStatus.approved if action.action == "approve" else ReviewStatus.rejected
    )

    after = {f: _serialize(getattr(vuln, f)) for f in _TRACKED}
    changes = {
        f: {"from": before[f], "to": after[f]}
        for f in _TRACKED
        if before[f] != after[f]
    }
    if changes:
        db.add(VulnHistory(
            vuln_id=vuln_id,
            user_id=reviewer.id,
            username=reviewer.username,
            changes=changes,
        ))

    await db.commit()
    await db.refresh(vuln)
    return vuln


async def bulk_update_status(
    db: AsyncSession,
    ids: list[uuid.UUID],
    status: Status,
    assigned_to: uuid.UUID | None = None,
) -> int:
    result = await db.execute(
        select(Vulnerability).where(
            Vulnerability.id.in_(ids),
            Vulnerability.deleted_at.is_(None),
        )
    )
    vulns = result.scalars().all()
    for vuln in vulns:
        vuln.status = status
        if assigned_to is not None:
            vuln.assigned_to = assigned_to
    await db.commit()
    return len(vulns)


async def delete_vuln(
    db: AsyncSession,
    vuln_id: uuid.UUID,
    current_user: User | None = None,
) -> bool:
    vuln = await get_vuln(db, vuln_id, current_user)
    if vuln is None:
        return False

    if current_user is not None:
        if current_user.role in ("admin", "manager"):
            pass
        elif current_user.role == "pentester":
            if vuln.created_by != current_user.id:
                raise HTTPException(status_code=403, detail="Can only delete your own vulnerabilities")
        else:
            raise HTTPException(status_code=403, detail="Insufficient permissions")

    vuln.deleted_at = datetime.now(timezone.utc)
    await db.commit()
    return True


async def export_vulns_csv(
    db: AsyncSession,
    current_user: User,
    status: Status | None = None,
    severity: Severity | None = None,
    target: str | None = None,
    search: str | None = None,
    assigned_to: uuid.UUID | None = None,
) -> str:
    vulns, _ = await list_vulns(
        db, current_user, status, None, severity, target, search, assigned_to,
        skip=0, limit=10_000,
    )

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "id", "title", "target", "severity", "status", "review_status",
        "cve_id", "cvss_score", "cvss_vector", "cwe_id",
        "assigned_to", "due_date", "created_by", "created_at", "updated_at",
    ])
    for v in vulns:
        writer.writerow([
            v.id, v.title, v.target, v.severity.value, v.status.value,
            v.review_status.value,
            v.cve_id or "", v.cvss_score if v.cvss_score is not None else "",
            v.cvss_vector or "", v.cwe_id or "",
            v.assigned_to or "", v.due_date.isoformat() if v.due_date else "",
            v.created_by, v.created_at.isoformat(), v.updated_at.isoformat(),
        ])
    return output.getvalue()


async def get_vuln_history(
    db: AsyncSession,
    vuln_id: uuid.UUID,
) -> list[VulnHistory]:
    result = await db.execute(
        select(VulnHistory)
        .where(VulnHistory.vuln_id == vuln_id)
        .order_by(VulnHistory.changed_at.desc())
    )
    return list(result.scalars().all())
