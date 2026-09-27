import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.comment import Comment
from app.models.user import User
from app.schemas.comment import CommentCreate, CommentResponse


async def list_comments(db: AsyncSession, vuln_id: uuid.UUID) -> list[CommentResponse]:
    rows = await db.execute(
        select(
            Comment.id,
            Comment.vuln_id,
            Comment.user_id,
            Comment.body,
            Comment.created_at,
            User.username,
        )
        .join(User, Comment.user_id == User.id)
        .where(Comment.vuln_id == vuln_id)
        .order_by(Comment.created_at)
    )
    return [
        CommentResponse(
            id=row.id,
            vuln_id=row.vuln_id,
            user_id=row.user_id,
            username=row.username,
            body=row.body,
            created_at=row.created_at,
        )
        for row in rows
    ]


async def create_comment(
    db: AsyncSession,
    vuln_id: uuid.UUID,
    user_id: uuid.UUID,
    data: CommentCreate,
) -> CommentResponse:
    comment = Comment(vuln_id=vuln_id, user_id=user_id, body=data.body.strip())
    db.add(comment)
    await db.commit()
    await db.refresh(comment)

    result = await db.execute(select(User.username).where(User.id == user_id))
    username = result.scalar_one()

    return CommentResponse(
        id=comment.id,
        vuln_id=comment.vuln_id,
        user_id=comment.user_id,
        username=username,
        body=comment.body,
        created_at=comment.created_at,
    )
