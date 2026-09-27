import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_roles
from app.models.user import User
from app.schemas.comment import CommentCreate, CommentResponse
from app.services.comment_service import create_comment, list_comments
from app.services.vuln_service import get_vuln

router = APIRouter(prefix="/vulns/{vuln_id}/comments", tags=["comments"])


@router.get("/", response_model=list[CommentResponse])
async def get_comments(
    vuln_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not await get_vuln(db, vuln_id):
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return await list_comments(db, vuln_id)


@router.post("/", response_model=CommentResponse, status_code=201)
async def post_comment(
    vuln_id: uuid.UUID,
    body: CommentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = require_roles("admin", "manager", "pentester", "developer"),
):
    if not await get_vuln(db, vuln_id):
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return await create_comment(db, vuln_id, current_user.id, body)
