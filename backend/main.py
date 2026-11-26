"""
خادم المشروع (FastAPI) — المرحلة 2
===================================
يوفّر:
  الواجهة:
    GET  /               → صفحة الويب
  الفحص:
    POST /api/scan       → يفحص كوداً، يحلّله بالـ AI، ويحفظه في القاعدة (إن كان المستخدم داخلاً)
  الحسابات:
    POST /api/register   → إنشاء حساب
    POST /api/login      → تسجيل دخول (يعيد توكن)
    POST /api/logout     → تسجيل خروج
    GET  /api/me         → بيانات المستخدم الحالي
  السجل:
    GET  /api/history    → قائمة فحوصات المستخدم السابقة
    GET  /api/scan/{id}  → تفاصيل فحص سابق

التشغيل:
  .venv\\Scripts\\python -m uvicorn backend.main:app --reload --port 8000
"""

from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.scanner import scan_code
from backend.ai_analysis import analyze, ai_status, dataset_stats
from backend.web_scanner import scan_website, ownership_token, verify_ownership, normalize_url
from backend.db import init_db, get_session, User, Scan
from backend.auth import (
    hash_password, verify_password, new_token,
    get_current_user, require_user,
)
from backend.rate_limit import scan_rate_limit

BASE_DIR = Path(__file__).resolve().parent.parent
FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(title="Cyber Shield AI", version="0.4.0 (Website Scan)")


@app.on_event("startup")
def _startup():
    init_db()  # ينشئ الجداول إن لم تكن موجودة


# ---------------------------------------------------------------- نماذج الطلبات
class ScanRequest(BaseModel):
    code: str
    filename: str = ""


class AuthRequest(BaseModel):
    username: str
    password: str


class WebScanRequest(BaseModel):
    url: str
    active: bool = False  # active checks require verified ownership


def _save_scan(db: Session, user: User, result: dict, target_name: str):
    """Persist a scan result (code or website) for a logged-in user."""
    s = result["summary"]
    rec = Scan(
        user_id=user.id,
        filename=target_name or "",
        language=result.get("language", "unknown"),
        lines_scanned=result.get("lines_scanned", 0),
        total_findings=result["total_findings"],
        security_score=result["security_score"],
        critical=s.get("critical", 0), high=s.get("high", 0),
        medium=s.get("medium", 0), low=s.get("low", 0),
        ai_summary=result.get("ai_summary", ""),
        result_json=result,
    )
    db.add(rec)
    db.commit()
    db.refresh(rec)
    return rec.id


# ---------------------------------------------------------------- صحة الخادم
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Cyber Shield AI", "version": "0.4.0-webscan"}


@app.get("/api/ai-status")
def ai_status_endpoint():
    """Current hybrid-AI mode: 'mock' (local) or 'claude' (real API)."""
    return ai_status()


@app.get("/api/dataset-stats")
def dataset_stats_endpoint():
    """Training-data stats collected so far (the research/hybrid angle)."""
    return dataset_stats()


# ---------------------------------------------------------------- الحسابات
@app.post("/api/register")
def register(req: AuthRequest, db: Session = Depends(get_session)):
    username = req.username.strip()
    if len(username) < 3 or len(req.password) < 6:
        raise HTTPException(400, "اسم المستخدم 3 أحرف+ وكلمة المرور 6 أحرف+")
    if db.query(User).filter(User.username == username).first():
        raise HTTPException(409, "اسم المستخدم مستخدم بالفعل")
    token = new_token()
    user = User(username=username, password_hash=hash_password(req.password), token=token)
    db.add(user)
    db.commit()
    return {"token": token, "username": username}


@app.post("/api/login")
def login(req: AuthRequest, db: Session = Depends(get_session)):
    user = db.query(User).filter(User.username == req.username.strip()).first()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(401, "بيانات الدخول غير صحيحة")
    user.token = new_token()  # توكن جديد لكل دخول
    db.commit()
    return {"token": user.token, "username": user.username}


@app.post("/api/logout")
def logout(user: User = Depends(require_user), db: Session = Depends(get_session)):
    user.token = None
    db.commit()
    return {"ok": True}


@app.get("/api/me")
def me(user: User | None = Depends(get_current_user)):
    if not user:
        return {"user": None}
    return {"user": {"id": user.id, "username": user.username}}


# ---------------------------------------------------------------- الفحص
@app.post("/api/scan")
def scan(
    req: ScanRequest,
    db: Session = Depends(get_session),
    user: User | None = Depends(get_current_user),
    _rl: None = Depends(scan_rate_limit),
):
    if not req.code.strip():
        return JSONResponse(status_code=400, content={"error": "الكود فارغ"})

    # 1) الفحص الثابت  2) تحليل الذكاء الاصطناعي
    result = scan_code(req.code, req.filename)
    result = analyze(result)

    # 3) الحفظ في القاعدة (فقط للمستخدمين المسجّلين)
    if user:
        s = result["summary"]
        rec = Scan(
            user_id=user.id,
            filename=req.filename or "",
            language=result["language"],
            lines_scanned=result["lines_scanned"],
            total_findings=result["total_findings"],
            security_score=result["security_score"],
            critical=s.get("critical", 0),
            high=s.get("high", 0),
            medium=s.get("medium", 0),
            low=s.get("low", 0),
            ai_summary=result.get("ai_summary", ""),
            result_json=result,
        )
        db.add(rec)
        db.commit()
        db.refresh(rec)
        result["scan_id"] = rec.id
        result["saved"] = True
    else:
        result["saved"] = False  # زائر: لا يُحفظ

    return result


# ---------------------------------------------------------------- فحص المواقع (المرحلة 4)
@app.get("/api/site/token")
def site_token(url: str, user: User = Depends(require_user)):
    """
    Returns the ownership-verification token for a target URL, plus instructions.
    The user must expose this token before an ACTIVE scan is allowed.
    """
    token = ownership_token(user.id, url)
    host = normalize_url(url)
    return {
        "token": token,
        "instructions": {
            "option_1_file": {
                "path": "/.well-known/cybershield-verify.txt",
                "content": token,
            },
            "option_2_meta": f'<meta name="cybershield-verify" content="{token}">',
        },
        "note": "Passive scans need no verification. Active scans require this token "
                "to be exposed on the site you own (localhost is auto-trusted).",
    }


@app.post("/api/web-scan")
def web_scan(
    req: WebScanRequest,
    db: Session = Depends(get_session),
    user: User | None = Depends(get_current_user),
    _rl: None = Depends(scan_rate_limit),
):
    url = normalize_url(req.url)
    if not url:
        return JSONResponse(status_code=400, content={"error": "empty URL"})

    active = bool(req.active)
    verification = None
    if active:
        # Active checks are gated behind ownership verification
        if not user:
            raise HTTPException(401, "Active scan requires sign-in")
        token = ownership_token(user.id, url)
        verification = verify_ownership(url, token)
        if not verification.get("verified"):
            # Deny active checks; tell the user how to verify
            return {
                "needs_verification": True,
                "token": token,
                "message": "Ownership not verified. Expose the token to run an active scan.",
            }

    # 1) website scan  2) AI analysis (reuses the same AI layer)
    result = scan_website(url, active=active)
    if "error" in result:
        return JSONResponse(status_code=400, content=result)
    result = analyze(result)
    if verification:
        result["ownership"] = verification

    # 3) save for logged-in users
    if user:
        result["scan_id"] = _save_scan(db, user, result, target_name=url)
        result["saved"] = True
    else:
        result["saved"] = False
    return result


# ---------------------------------------------------------------- السجل
@app.get("/api/history")
def history(user: User = Depends(require_user), db: Session = Depends(get_session)):
    rows = (
        db.query(Scan)
        .filter(Scan.user_id == user.id)
        .order_by(Scan.created_at.desc())
        .limit(50)
        .all()
    )
    return {
        "scans": [
            {
                "id": r.id,
                "filename": r.filename,
                "language": r.language,
                "security_score": r.security_score,
                "total_findings": r.total_findings,
                "critical": r.critical,
                "high": r.high,
                "medium": r.medium,
                "low": r.low,
                "created_at": r.created_at.isoformat(timespec="seconds"),
            }
            for r in rows
        ]
    }


@app.get("/api/scan/{scan_id}")
def get_scan(
    scan_id: int,
    user: User = Depends(require_user),
    db: Session = Depends(get_session),
):
    rec = db.query(Scan).filter(Scan.id == scan_id, Scan.user_id == user.id).first()
    if not rec:
        raise HTTPException(404, "الفحص غير موجود")
    return rec.result_json


# ---------------------------------------------------------------- الواجهة
@app.get("/")
def index():
    return FileResponse(FRONTEND_DIR / "index.html")


app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")
