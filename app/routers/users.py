import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.dependencies import get_current_user, get_db, require_admin
from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.user import UserCreate, UserPasswordChange, UserResponse
from app.services.user_service import (
    activate_user,
    change_password,
    create_user,
    deactivate_user,
    delete_user,
    list_all_users,
    list_users,
)

router = APIRouter(prefix="/users", tags=["users"])


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: User = Depends(get_current_user)):
    return current_user


@router.get("/", response_model=list[UserResponse])
async def get_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if current_user.role == "admin":
        return await list_all_users(db)
    return await list_users(db)


@router.post("/", response_model=UserResponse, status_code=201)
async def post_user(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    try:
        return await create_user(db, body)
    except ValueError:
        raise HTTPException(status_code=409, detail="Username already taken")


@router.patch("/{user_id}/deactivate", response_model=UserResponse)
async def deactivate(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    try:
        user = await deactivate_user(db, user_id, current_user.id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.patch("/{user_id}/activate", response_model=UserResponse)
async def activate(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_admin),
):
    user = await activate_user(db, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@router.delete("/{user_id}", status_code=204)
async def delete(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    try:
        found = await delete_user(db, user_id, current_user.id)
    except ValueError as e:
        if str(e) == "has_vulnerabilities":
            raise HTTPException(
                status_code=409,
                detail="Cannot delete a user who has reported vulnerabilities. Deactivate instead.",
            )
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    if not found:
        raise HTTPException(status_code=404, detail="User not found")


@router.get("/me/stats")
async def get_my_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    created = await db.scalar(
        select(func.count()).where(
            Vulnerability.created_by == current_user.id,
            Vulnerability.deleted_at.is_(None),
        )
    )
    assigned = await db.scalar(
        select(func.count()).where(
            Vulnerability.assigned_to == current_user.id,
            Vulnerability.deleted_at.is_(None),
        )
    )
    return {"vulns_created": created or 0, "vulns_assigned": assigned or 0}


@router.post("/me/password", status_code=204)
async def update_password(
    body: UserPasswordChange,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    ok = await change_password(db, current_user, body.current_password, body.new_password)
    if not ok:
        raise HTTPException(status_code=400, detail="Current password is incorrect")
