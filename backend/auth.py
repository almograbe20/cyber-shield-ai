"""
نظام المصادقة (Authentication) — المرحلة 2
===========================================
تسجيل دخول بسيط مناسب للـ MVP:
  - كلمة المرور تُخزَّن مُجزّأة بـ PBKDF2-HMAC-SHA256 مع ملح عشوائي (من مكتبة hashlib القياسية).
  - بعد الدخول يُعطى المستخدم توكن عشوائي يُخزَّن في القاعدة ويُرسَل مع كل طلب.

ملاحظة شريك (صريحة): هذا مستوى MVP. قبل الإنتاج الحقيقي يُفضّل:
  JWT، HTTPS إجباري، تحديد معدّل محاولات الدخول (Rate Limiting)، وانتهاء صلاحية التوكن.
"""

import hashlib
import secrets

from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session

from backend.db import User, get_session

_ITERATIONS = 200_000


def hash_password(password: str) -> str:
    """ينتج سلسلة بالشكل:  pbkdf2$<iterations>$<salt_hex>$<hash_hex>"""
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2${_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iters, salt_hex, hash_hex = stored.split("$")
        dk = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), int(iters)
        )
        # مقارنة ثابتة الزمن لمنع هجمات التوقيت
        return secrets.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


def new_token() -> str:
    return secrets.token_hex(32)


def get_current_user(
    authorization: str = Header(default=""),
    db: Session = Depends(get_session),
) -> User | None:
    """
    يقرأ التوكن من ترويسة Authorization ويعيد المستخدم.
    اختياري: يعيد None للزوار (يُسمح بالفحص المجهول).
    """
    if not authorization:
        return None
    token = authorization.replace("Bearer ", "").strip()
    if not token:
        return None
    user = db.query(User).filter(User.token == token).first()
    if user and getattr(user, "is_blocked", False):
        return None  # محظور: نعامله كغير مسجّل
    return user


def require_user(user: User | None = Depends(get_current_user)) -> User:
    """نسخة إلزامية: ترفض الطلب إن لم يكن المستخدم مسجّلاً."""
    if user is None:
        raise HTTPException(status_code=401, detail="مطلوب تسجيل الدخول")
    return user


def require_admin(user: User = Depends(require_user)) -> User:
    """يرفض الطلب إن لم يكن المستخدم أدمن."""
    if not getattr(user, "is_admin", False):
        raise HTTPException(status_code=403, detail="صلاحية الأدمن مطلوبة")
    return user
