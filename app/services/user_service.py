import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.user import User
from app.models.vulnerability import Vulnerability
from app.schemas.user import UserCreate
from app.services.auth_service import hash_password, verify_password


async def list_users(db: AsyncSession) -> list[User]:
    result = await db.execute(
        select(User).where(User.is_active.is_(True)).order_by(User.username)
    )
    return list(result.scalars().all())


async def list_all_users(db: AsyncSession) -> list[User]:
    result = await db.execute(select(User).order_by(User.username))
    return list(result.scalars().all())


async def create_user(db: AsyncSession, data: UserCreate) -> User:
    existing = await db.execute(select(User).where(User.username == data.username))
    if existing.scalar_one_or_none() is not None:
        raise ValueError("username_taken")

    user = User(
        username=data.username,
        hashed_password=hash_password(data.password),
        role=data.role,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)
    return user


async def deactivate_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    requesting_user_id: uuid.UUID,
) -> User | None:
    if user_id == requesting_user_id:
        raise ValueError("cannot_deactivate_self")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        return None

    user.is_active = False
    await db.commit()
    await db.refresh(user)
    return user


async def activate_user(
    db: AsyncSession,
    user_id: uuid.UUID,
) -> User | None:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        return None

    user.is_active = True
    await db.commit()
    await db.refresh(user)
    return user


async def delete_user(
    db: AsyncSession,
    user_id: uuid.UUID,
    requesting_user_id: uuid.UUID,
) -> bool:
    if user_id == requesting_user_id:
        raise ValueError("cannot_delete_self")

    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        return False

    count_result = await db.execute(
        select(func.count()).where(Vulnerability.created_by == user_id)
    )
    if count_result.scalar_one() > 0:
        raise ValueError("has_vulnerabilities")

    await db.delete(user)
    await db.commit()
    return True


async def change_password(
    db: AsyncSession,
    user: User,
    current_password: str,
    new_password: str,
) -> bool:
    if not verify_password(current_password, user.hashed_password):
        return False

    user.hashed_password = hash_password(new_password)
    await db.commit()
    return True
