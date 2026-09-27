import asyncio

from app.database import AsyncSessionLocal
from app.models.user import User
from app.services.auth_service import hash_password


async def create_user():
    async with AsyncSessionLocal() as db:
        user = User(username="admin", hashed_password=hash_password("admin123"))
        db.add(user)
        await db.commit()
        print(f"Created user: {user.username}")


asyncio.run(create_user())
