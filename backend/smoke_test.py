"""اختبار دخاني شامل للمرحلة 2 عبر الـ API الحيّ."""
import json, urllib.request, urllib.error, sys, time, os

BASE = os.getenv("VULNSCAN_BASE", "http://127.0.0.1:8000")

def call(method, path, data=None, token=None):
    url = BASE + path
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    if body:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode())

SAMPLE = 'password = "SuperSecret123"\nimport os\nos.system("ping " + host)\nquery = "SELECT * FROM users WHERE id=" + uid'

def main():
    out = []
    uname = "student_" + str(int(time.time()))
    # 1) تسجيل
    st, d = call("POST", "/api/register", {"username": uname, "password": "pass1234"})
    out.append(f"register: {st} user={d.get('username')}")
    assert st == 200 and d.get("token"), d
    token = d["token"]
    # 2) فحص مجهول (بدون توكن) -> لا يُحفظ
    st, d = call("POST", "/api/scan", {"code": SAMPLE, "filename": "a.py"})
    out.append(f"anon scan: {st} saved={d.get('saved')} findings={d.get('total_findings')}")
    assert st == 200 and d.get("saved") is False
    # 3) فحص مسجّل -> يُحفظ
    st, d = call("POST", "/api/scan", {"code": SAMPLE, "filename": "login.py"}, token)
    out.append(f"auth scan: {st} saved={d.get('saved')} id={d.get('scan_id')} score={d.get('security_score')}")
    assert st == 200 and d.get("saved") is True
    scan_id = d["scan_id"]
    # 4) فحص ثانٍ لإثبات السجل المتعدد
    call("POST", "/api/scan", {"code": "DEBUG = True", "filename": "conf.py"}, token)
    # 5) السجل
    st, d = call("GET", "/api/history", token=token)
    out.append(f"history: {st} count={len(d.get('scans', []))}")
    assert st == 200 and len(d["scans"]) == 2
    # 6) عرض فحص سابق
    st, d = call("GET", f"/api/scan/{scan_id}", token=token)
    out.append(f"view scan: {st} findings={d.get('total_findings')} ai_mode={d.get('ai_mode')}")
    assert st == 200 and "findings" in d
    # 7) منع الوصول بدون توكن
    st, d = call("GET", "/api/history")
    out.append(f"history no-auth: {st} (expected 401)")
    assert st == 401
    # 8) دخول خاطئ
    st, d = call("POST", "/api/login", {"username": uname, "password": "wrong"})
    out.append(f"bad login: {st} (expected 401)")
    assert st == 401
    # 9) دخول صحيح
    st, d = call("POST", "/api/login", {"username": uname, "password": "pass1234"})
    out.append(f"login: {st} got_token={bool(d.get('token'))}")
    assert st == 200 and d.get("token")

    print("\n".join(out))
    print("\n[OK] ALL PASSED")

if __name__ == "__main__":
    main()
