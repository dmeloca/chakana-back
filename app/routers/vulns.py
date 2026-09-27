import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_roles
from app.models.user import User
from app.models.vulnerability import ReviewStatus, Severity, Status
from app.schemas.vuln_history import VulnHistoryEntry
from app.schemas.vulnerability import (
    BulkStatusUpdate,
    ReviewAction,
    VulnerabilityCreate,
    VulnerabilityListResponse,
    VulnerabilityResponse,
    VulnerabilityUpdate,
)
from app.services.vuln_service import (
    bulk_update_status,
    create_vuln,
    delete_vuln,
    export_vulns_csv,
    get_vuln,
    get_vuln_history,
    list_vulns,
    review_vuln,
    update_vuln,
)

router = APIRouter(prefix="/vulns", tags=["vulns"])


@router.get("/export")
async def export_vulns(
    status: Status | None = None,
    severity: Severity | None = None,
    target: str | None = None,
    search: str | None = None,
    assigned_to: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = require_roles("admin", "manager", "pentester", "developer", "reviewer"),
):
    csv_data = await export_vulns_csv(db, current_user, status, severity, target, search, assigned_to)
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=vulnerabilities.csv"},
    )


@router.patch("/bulk", status_code=200)
async def bulk_update(
    body: BulkStatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = require_roles("admin", "manager"),
):
    count = await bulk_update_status(db, body.ids, body.status, body.assigned_to)
    return {"updated": count}


@router.get("/", response_model=VulnerabilityListResponse)
async def get_vulns(
    status: Status | None = None,
    review_status: ReviewStatus | None = None,
    severity: Severity | None = None,
    target: str | None = None,
    search: str | None = None,
    assigned_to: uuid.UUID | None = None,
    skip: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    items, total = await list_vulns(
        db, current_user, status, review_status, severity, target, search, assigned_to, skip, limit,
    )
    return VulnerabilityListResponse(items=items, total=total, skip=skip, limit=limit)


@router.post("/", response_model=VulnerabilityResponse, status_code=201)
async def post_vuln(
    body: VulnerabilityCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = require_roles("admin", "pentester"),
):
    return await create_vuln(db, body, current_user.id, current_user.role)


@router.get("/{vuln_id}", response_model=VulnerabilityResponse)
async def get_one(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vuln = await get_vuln(db, vuln_id, current_user)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.put("/{vuln_id}", response_model=VulnerabilityResponse)
async def put_vuln(
    vuln_id: uuid.UUID,
    body: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vuln = await update_vuln(db, vuln_id, body, current_user)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.patch("/{vuln_id}/review", response_model=VulnerabilityResponse)
async def patch_review(
    vuln_id: uuid.UUID,
    body: ReviewAction,
    db: AsyncSession = Depends(get_db),
    current_user: User = require_roles("admin", "reviewer"),
):
    vuln = await review_vuln(db, vuln_id, body, current_user)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return vuln


@router.get("/{vuln_id}/history", response_model=list[VulnHistoryEntry])
async def get_history(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    vuln = await get_vuln(db, vuln_id, current_user)
    if vuln is None:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return await get_vuln_history(db, vuln_id)


@router.delete("/{vuln_id}", status_code=204)
async def del_vuln(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    deleted = await delete_vuln(db, vuln_id, current_user)
    if not deleted:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return Response(status_code=204)
