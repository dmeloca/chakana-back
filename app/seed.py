import asyncio
import random
from datetime import datetime, timedelta, timezone

from sqlalchemy import select

from app.database import AsyncSessionLocal
from app.models.user import User
from app.models.vulnerability import Severity, Status, Vulnerability
from app.services.auth_service import hash_password

USERS = [
    {"username": "admin", "password": "admin123", "role": "admin"},
    {"username": "pentester", "password": "pentester123", "role": "pentester"},
]

TARGETS = [
    "api.example.com",
    "app.example.com",
    "auth.example.com",
    "db.example.com",
    "192.168.1.10",
    "192.168.1.20",
    "https://admin.example.com",
    "mail.example.com",
]

VULNS = [
    ("SQL Injection in login form", Severity.critical),
    ("Reflected XSS in search", Severity.high),
    ("Missing rate limiting on API", Severity.medium),
    ("Outdated TLS version", Severity.medium),
    ("Exposed debug endpoint", Severity.high),
    ("Weak password policy", Severity.medium),
    ("IDOR on user profile", Severity.high),
    ("Open redirect vulnerability", Severity.low),
    ("Missing HSTS header", Severity.low),
    ("Directory traversal attempt", Severity.critical),
    ("Broken access control on admin panel", Severity.critical),
    ("Sensitive data in logs", Severity.high),
    ("CSRF on state-changing endpoints", Severity.high),
    ("Unvalidated file upload", Severity.critical),
    ("Hardcoded credentials in config", Severity.critical),
    ("JWT algorithm confusion", Severity.high),
    ("Missing Content-Security-Policy", Severity.low),
    ("Insecure direct object reference", Severity.medium),
    ("Clickjacking vulnerability", Severity.low),
    ("XML External Entity injection", Severity.critical),
    ("Server-Side Request Forgery", Severity.high),
    ("Insecure deserialization", Severity.critical),
    ("Unrestricted file inclusion", Severity.high),
    ("Verbose error messages", Severity.low),
    ("Missing input sanitization", Severity.medium),
]

STATUSES = (
    [Status.open] * 12
    + [Status.in_progress] * 8
    + [Status.closed] * 5
)


async def seed():
    async with AsyncSessionLocal() as db:
        # create users (skip existing, update role if needed)
        users = []
        for u in USERS:
            result = await db.execute(select(User).where(User.username == u["username"]))
            user = result.scalar_one_or_none()
            if user is None:
                user = User(
                    username=u["username"],
                    hashed_password=hash_password(u["password"]),
                    role=u["role"],
                )
                db.add(user)
            else:
                user.role = u["role"]
            users.append(user)
        await db.flush()

        # create vulnerabilities spread over last 12 weeks
        now = datetime.now(timezone.utc)
        random.shuffle(STATUSES)

        for i, (title, severity) in enumerate(VULNS):
            weeks_ago = random.randint(0, 11)
            days_ago = random.randint(0, 6)
            created = now - timedelta(weeks=weeks_ago, days=days_ago)
            st = STATUSES[i]

            vuln = Vulnerability(
                title=title,
                description=f"Detailed description for: {title}.",
                evidence=f"Evidence collected during assessment of {title.lower()}.",
                target=random.choice(TARGETS),
                severity=severity,
                status=st,
                created_by=random.choice(users).id,
            )
            db.add(vuln)
            vuln.created_at = created
            vuln.updated_at = created if st == Status.open else created + timedelta(days=random.randint(1, 5))
            if st == Status.closed:
                vuln.deleted_at = None

        await db.commit()
        print(f"Seeded {len(USERS)} users and {len(VULNS)} vulnerabilities.")


if __name__ == "__main__":
    asyncio.run(seed())
