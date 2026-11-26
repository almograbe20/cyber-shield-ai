"""
Startup bootstrap — Cyber Shield AI
===================================
Runs once when the server starts:
  1) ensures the `is_admin` column exists (for databases created before it was added)
  2) ensures an admin account exists

Admin credentials come from environment variables, falling back to defaults:
  ADMIN_EMAIL     (default: cyber_shield@gmail.com)
  ADMIN_PASSWORD  (default: admin123)

SECURITY NOTE: the default password is only suitable for a local demo / project.
For any public deployment, set ADMIN_EMAIL / ADMIN_PASSWORD in the environment
to strong values (and never commit real secrets).
"""

import os

from sqlalchemy import text

from backend.db import engine, SessionLocal, User
from backend.auth import hash_password

DEFAULT_ADMIN_EMAIL = "cyber_shield@gmail.com"
DEFAULT_ADMIN_PASSWORD = "admin123"


def _ensure_schema():
    """Add the is_admin column to pre-existing databases (no-op if it exists)."""
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE users ADD COLUMN is_admin BOOLEAN DEFAULT 0"))
            conn.commit()
        except Exception:
            pass  # column already exists → fine


def ensure_admin():
    """Create (or upgrade) the admin account."""
    _ensure_schema()
    email = os.getenv("ADMIN_EMAIL", DEFAULT_ADMIN_EMAIL)
    password = os.getenv("ADMIN_PASSWORD", DEFAULT_ADMIN_PASSWORD)

    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == email).first()
        if admin is None:
            admin = User(
                username=email,
                password_hash=hash_password(password),
                is_admin=True,
            )
            db.add(admin)
        else:
            admin.is_admin = True  # make sure the account stays admin
        db.commit()
    finally:
        db.close()
