"""
طبقة قاعدة البيانات (Database Layer) — المرحلة 2
================================================
نستخدم SQLAlchemy مع SQLite في الـ MVP.
الانتقال لـ PostgreSQL لاحقاً = تغيير DATABASE_URL فقط (سطر واحد).

الجداول:
  - users : حسابات المستخدمين (username + كلمة مرور مُجزّأة + توكن جلسة)
  - scans : كل عملية فحص (مرتبطة بمستخدم، مع النتائج كاملة بصيغة JSON)
"""

import datetime
from pathlib import Path

from sqlalchemy import (
    create_engine, Column, Integer, String, Text, DateTime, ForeignKey, JSON, Boolean
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

# ملف القاعدة بجانب الكود. لاحقاً: "postgresql://user:pass@host/db"
DB_PATH = Path(__file__).parent / "vulnscan.db"
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # مطلوب لـ SQLite مع FastAPI
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)   # pbkdf2$...
    token = Column(String(64), nullable=True, index=True)  # توكن الجلسة الحالي
    is_admin = Column(Boolean, default=False)              # حساب أدمن يرى كل المستخدمين
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    scans = relationship("Scan", back_populates="user", cascade="all, delete-orphan")


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # يسمح بفحص مجهول

    filename = Column(String(255), default="")
    language = Column(String(32), default="unknown")
    lines_scanned = Column(Integer, default=0)
    total_findings = Column(Integer, default=0)
    security_score = Column(Integer, default=100)

    # عدّادات الخطورة (لعرض السجل بسرعة بدون فك الـ JSON)
    critical = Column(Integer, default=0)
    high = Column(Integer, default=0)
    medium = Column(Integer, default=0)
    low = Column(Integer, default=0)

    ai_summary = Column(Text, default="")
    result_json = Column(JSON)  # التقرير الكامل (findings + كل شيء)

    created_at = Column(DateTime, default=datetime.datetime.utcnow)

    user = relationship("User", back_populates="scans")


def init_db():
    """ينشئ الجداول إن لم تكن موجودة. يُستدعى عند إقلاع الخادم."""
    Base.metadata.create_all(bind=engine)


def get_session():
    """جلسة قاعدة بيانات تُغلق تلقائياً (dependency لـ FastAPI)."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
