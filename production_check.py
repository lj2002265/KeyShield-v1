# -*- coding: utf-8 -*-
"""钥盾生产模式安全自检。使用临时数据目录，不读取或修改正式数据库。"""
import os
import tempfile
import io
import sys

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")

tmp = tempfile.TemporaryDirectory(prefix="keyshield-production-check-")
os.environ.update({
    "KEYSHIELD_ENV": "production",
    "KEYSHIELD_DEMO_MODE": "0",
    "KEYSHIELD_REQUIRE_INVITE": "0",
    "KEYSHIELD_ALLOW_DIRECT": "0",
    "KEYSHIELD_DEMO_BILLING": "0",
    "KEYSHIELD_DATA_DIR": tmp.name,
})

import app as target
from werkzeug.security import generate_password_hash

sent_codes = {}
def capture_email(email, code, purpose):
    sent_codes[(purpose, email)] = code
    return True
target.EMAIL_MODE = "smtp"
target.EMAIL_READY = True
target.deliver_email_code = capture_email

PASS = 0
FAIL = 0

def check(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        print("✅", name)
    else:
        FAIL += 1
        print("❌", name, detail)

check("生产模式默认强制安全 Cookie", target.app.config["SESSION_COOKIE_SECURE"] is True)

secure_probe = target.app.test_client().get("/api/health", base_url="https://keyshield.example")
check("HTTPS 响应启用 HSTS", "Strict-Transport-Security" in secure_probe.headers)

plain_probe = target.app.test_client().get("/api/health", base_url="http://keyshield.example")
check("HTTP 响应不误发 HSTS", "Strict-Transport-Security" not in plain_probe.headers)

ADMIN_PASSWORD = "Prod-Check-Admin-2026"
salt, _, wrapped = target.build_user_key_material(ADMIN_PASSWORD)
with target.app.app_context():
    db = target.get_db()
    db.execute("""INSERT INTO users(username,pw_hash,salt,role,active,phone,wrapped_key,created)
        VALUES(?,?,?,'admin',1,?,?,?)""",
        ("prod_admin", generate_password_hash(ADMIN_PASSWORD), salt, "13800000001", wrapped, target.now_str()))
    db.commit()

admin = target.app.test_client()
visitor = target.app.test_client()

r = visitor.get("/api/public-config")
cfg = r.get_json()
check("生产配置仅需邮箱验证且关闭演示/直发", r.status_code == 200 and not cfg["invite_required"]
      and not cfg["demo_mode"] and not cfg["direct_mode"] and cfg["email_ready"]
      and not cfg["email_demo"], str(cfg))

r = visitor.post("/api/sms/send", json={"phone": "13800000002"})
check("生产环境关闭演示短信", r.status_code == 503 and not r.get_json()["ok"], r.get_data(as_text=True))

r = admin.post("/api/login", json={"username": "prod_admin", "password": ADMIN_PASSWORD})
check("服务器初始化管理员可登录", r.status_code == 200 and r.get_json()["ok"], r.get_data(as_text=True))

admin_email = "prod_admin@example.test"
r = admin.post("/api/email/send", json={"email": admin_email, "purpose": "bind"})
bind_code = sent_codes.get(("bind", admin_email), "")
r = admin.post("/api/email/bind", json={"email": admin_email, "email_code": bind_code,
    "current_password": ADMIN_PASSWORD})
check("旧账号可验证绑定邮箱并初始化恢复密钥", r.status_code == 200
      and r.get_json().get("recovery_key", "").startswith("KS-REC-"), r.get_data(as_text=True))

r = admin.post("/api/subscription/activate-demo", json={"plan": "self_hosted"})
check("生产环境禁止演示订阅开通", r.status_code == 403 and not r.get_json()["ok"], r.get_data(as_text=True))

r = admin.post("/api/invitations", json={"hours": 1, "max_uses": 1})
invite = r.get_json().get("invitation", "")
check("管理员生成一次性邀请码", r.status_code == 200 and invite.startswith("KS-"), r.get_data(as_text=True))

prod_email = "prod_user@example.test"
r = visitor.post("/api/email/send", json={"email": prod_email, "purpose": "register"})
register_code = sent_codes.get(("register", prod_email), "")
check("生产邮件通道发送注册验证码且响应不回显", r.status_code == 200 and register_code
      and not r.get_json().get("demo_code"), r.get_data(as_text=True))
r = visitor.post("/api/register", json={"username": "prod_user", "email": prod_email,
    "email_code": register_code, "password": "Prod-User-2026"})
registered = r.get_json()
recovery_key = registered.get("recovery_key", "")
check("无需邀请码、仅凭邮箱验证码注册普通用户", r.status_code == 200 and registered.get("role") == "user"
      and recovery_key.startswith("KS-REC-"), r.get_data(as_text=True))
with target.app.app_context():
    recovery_row = target.get_db().execute("""SELECT recovery_wrapped_key FROM users
        WHERE username='prod_user'""").fetchone()
check("恢复密钥明文不入库", bool(recovery_row["recovery_wrapped_key"])
      and recovery_key not in recovery_row["recovery_wrapped_key"])

r = visitor.post("/api/email/send", json={"email": prod_email, "purpose": "reset"})
reset_code = sent_codes.get(("reset", prod_email), "")
r = visitor.post("/api/password/recover", json={"identifier": prod_email,
    "email_code": reset_code, "recovery_key": recovery_key, "new_password": "Prod-User-New-2026"})
reset_ok = r.status_code == 200 and r.get_json().get("ok")
r = visitor.post("/api/login", json={"username": prod_email, "password": "Prod-User-New-2026"})
check("邮箱验证码与恢复密钥共同找回密码", reset_ok and r.status_code == 200
      and r.get_json().get("ok"), r.get_data(as_text=True))

with target.app.app_context():
    prod_user_id = target.get_db().execute("SELECT id FROM users WHERE username='prod_user'").fetchone()["id"]
r = admin.post(f"/api/users/{prod_user_id}/role", json={"role": "admin",
    "current_password": ADMIN_PASSWORD})
missing_stepup_rejected = r.status_code == 403 and not r.get_json().get("ok")
r = admin.post("/api/email/send", json={"purpose": "stepup", "email": ""})
stepup_code = sent_codes.get(("stepup", admin_email), "")
r = admin.post(f"/api/users/{prod_user_id}/role", json={"role": "admin",
    "current_password": ADMIN_PASSWORD, "email_code": stepup_code})
stepup_granted = r.status_code == 200 and r.get_json().get("role") == "admin"
check("管理员敏感授权要求密码与邮箱二次验证", missing_stepup_rejected and stepup_granted,
      r.get_data(as_text=True))
r = admin.post("/api/email/send", json={"purpose": "stepup", "email": ""})
stepup_code = sent_codes.get(("stepup", admin_email), "")
r = admin.post(f"/api/users/{prod_user_id}/role", json={"role": "user",
    "current_password": ADMIN_PASSWORD, "email_code": stepup_code})
check("敏感操作二次验证码单次使用且可完成权限回收", r.status_code == 200
      and r.get_json().get("role") == "user", r.get_data(as_text=True))

other = target.app.test_client()
other_email = "prod_user_2@example.test"
r = other.post("/api/email/send", json={"email": other_email, "purpose": "register"})
other_code = sent_codes.get(("register", other_email), "")
r = other.post("/api/register", json={"username": "prod_user_2", "email": other_email,
    "email_code": other_code, "password": "Prod-User-2026"})
check("邮箱验证码可独立注册第二个普通用户", r.status_code == 200
      and r.get_json().get("role") == "user", r.get_data(as_text=True))

r = admin.post("/api/shared", json={"name": "禁止直发", "cat": "DeepSeek",
    "value": "sk-production-check-1234567890", "mode": "direct"})
check("生产环境禁止托管密钥直发", r.status_code == 403 and not r.get_json()["ok"], r.get_data(as_text=True))

r = admin.post("/api/shared", json={"name": "生产代理资源", "cat": "DeepSeek",
    "value": "sk-production-virtual-key-1234567890", "mode": "proxy", "model": "deepseek-chat"})
resource_id = r.get_json().get("id", -1)
check("生产环境允许仅代理托管资源", r.status_code == 200 and resource_id > 0, r.get_data(as_text=True))
r = visitor.post(f"/api/shared/{resource_id}/grant", json={})
check("普通成员可领用代理资源", r.status_code == 200 and r.get_json().get("ok"), r.get_data(as_text=True))
r = visitor.post("/api/virtual-keys", json={"key_id": resource_id, "name": "CI",
    "days": 1, "daily_limit": 2})
virtual = r.get_json()
virtual_id = virtual.get("id", -1)
virtual_token = virtual.get("api_key", "")
check("生产环境签发成员专属 ks_ 虚拟 Key", r.status_code == 200 and
      virtual_token.startswith("ks_live_") and virtual_id > 0, r.get_data(as_text=True))
with target.app.app_context():
    db = target.get_db()
    stored = db.execute("SELECT token_hash,token_prefix FROM virtual_keys WHERE id=?", (virtual_id,)).fetchone()
check("虚拟 Key 明文不入库", bool(stored) and stored["token_hash"] != virtual_token and
      stored["token_prefix"] == virtual_token[:16])
r = visitor.get("/v1/models", headers={"Authorization": "Bearer " + virtual_token})
check("OpenAI 兼容模型接口接受虚拟 Key", r.status_code == 200 and
      r.get_json().get("object") == "list", r.get_data(as_text=True))
original_call_provider = target.call_provider
target.call_provider = lambda provider, api_key, model, prompt: (
    "security-check-ok", {"input_tokens": 4, "output_tokens": 2, "total_tokens": 6})
try:
    r = visitor.post("/v1/chat/completions", headers={"Authorization": "Bearer " + virtual_token},
        json={"model": "deepseek-chat", "messages": [{"role": "user", "content": "hello"}]})
finally:
    target.call_provider = original_call_provider
completion = r.get_json()
check("标准兼容调用只返回回答与用量、不下发厂商 Key", r.status_code == 200 and
      completion.get("object") == "chat.completion" and
      completion.get("usage", {}).get("total_tokens") == 6 and
      "sk-production-virtual-key" not in r.get_data(as_text=True), r.get_data(as_text=True))
r = visitor.delete(f"/api/virtual-keys/{virtual_id}", json={})
revoked_ok = r.status_code == 200 and r.get_json().get("ok")
r = visitor.get("/v1/models", headers={"Authorization": "Bearer " + virtual_token})
check("虚拟 Key 撤销后立即拒绝", revoked_ok and r.status_code == 401, r.get_data(as_text=True))

r = admin.post("/api/demo", json={})
check("生产环境禁止注入演示数据", r.status_code == 403 and not r.get_json()["ok"], r.get_data(as_text=True))

r = admin.post("/api/invitations", data="{}", content_type="text/plain")
check("写接口拒绝非 JSON 请求", r.status_code == 415, r.get_data(as_text=True))

r = admin.post("/api/invitations", json={}, headers={"Origin": "https://evil.example"})
check("写接口拒绝跨站来源", r.status_code == 403, r.get_data(as_text=True))

r = visitor.get("/api/health", base_url="https://keyshield.example")
check("健康检查与安全响应头正常", r.status_code == 200
      and r.headers.get("X-Frame-Options") == "DENY"
      and "max-age=" in r.headers.get("Strict-Transport-Security", ""), str(dict(r.headers)))

integrity_before = target.verify_audit_chain()
with target.app.app_context():
    db = target.get_db()
    audit_row = db.execute("SELECT id,detail FROM logs ORDER BY id DESC LIMIT 1").fetchone()
    original_detail = audit_row["detail"]
    db.execute("UPDATE logs SET detail=? WHERE id=?", (original_detail + "[tampered]", audit_row["id"]))
    db.commit()
integrity_tampered = target.verify_audit_chain()
with target.app.app_context():
    db = target.get_db()
    db.execute("UPDATE logs SET detail=? WHERE id=?", (original_detail, audit_row["id"]))
    db.commit()
integrity_restored = target.verify_audit_chain()
check("审计链可检出内容篡改且恢复原文后重新通过", integrity_before["ok"] and
      not integrity_tampered["ok"] and integrity_tampered["broken_id"] == audit_row["id"] and
      integrity_restored["ok"], str(integrity_tampered))

tmp.cleanup()
print(f"\n生产安全自检：{PASS} 通过 / {FAIL} 失败")
raise SystemExit(1 if FAIL else 0)
