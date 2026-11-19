# -*- coding: utf-8 -*-
"""钥盾 KeyShield · 端到端自检 v3.3(自检账号由脚本在数据库预置,不依赖公网注册)
跑完整流程后自动清理测试账号与测试托管密钥,不影响现有数据。"""
import json, urllib.request, urllib.error, http.cookiejar, sys, io, time, sqlite3, os, zipfile

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
BASE = os.environ.get("KEYSHIELD_BASE_URL", "http://127.0.0.1:8800").rstrip("/")
HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "keyshield.db")

ts = str(int(time.time()))[-6:]
ADMIN = f"check_admin_{ts}"
TEACH = f"check_teacher_{ts}"
RES = f"check_res_{ts}"
PWD = "chk123456"

PASS = 0; FAIL = 0
def check(name, cond, detail=""):
    global PASS, FAIL
    if cond: PASS += 1
    else: FAIL += 1
    print(f"{'✅' if cond else '❌'} {name}" + (f"  [{detail}]" if detail else ""))

def mk():
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    return op, cj

def req(op, path, body=None, method="GET"):
    data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method,
        headers={"Content-Type": "application/json"})
    try:
        with op.open(r, timeout=15) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try: return json.loads(e.read().decode())
        except Exception: return {"ok": False, "err": f"HTTP {e.code}"}

def req_binary(op, path):
    r = urllib.request.Request(BASE + path, method="GET")
    try:
        with op.open(r, timeout=20) as resp:
            return resp.status, dict(resp.headers), resp.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()

def req_bearer(path, token, body=None, method="GET"):
    data = json.dumps(body, ensure_ascii=False).encode() if body is not None else None
    r = urllib.request.Request(BASE + path, data=data, method=method, headers={
        "Content-Type": "application/json", "Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:  # nosec B310 - 固定本机自检地址
            return resp.status, json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        try: return e.code, json.loads(e.read().decode())
        except Exception: return e.code, {"ok": False, "err": f"HTTP {e.code}"}

def cleanup_all():
    """清扫所有自检残留账号/数据(含历史崩溃留下的孤儿)"""
    db = sqlite3.connect(DB)
    for row in db.execute("SELECT id,username FROM users WHERE username LIKE 'check_%' OR username LIKE 'chk_reg_%'").fetchall():
        uid, name = row
        db.execute("DELETE FROM subscriptions WHERE user_id=?", (uid,))
        db.execute("DELETE FROM entries WHERE user_id=?", (uid,))
        db.execute("DELETE FROM grants WHERE user_id=?", (uid,))
        db.execute("DELETE FROM usage_records WHERE user_id=?", (uid,))
        db.execute("DELETE FROM virtual_keys WHERE user_id=?", (uid,))
        db.execute("DELETE FROM users WHERE id=?", (uid,))
    # 团队:先清成员关系,再清团队密钥,最后清团队(按 [CHECK] 名称或 check_ 用户兜底)
    db.execute("""DELETE FROM team_members WHERE team_id IN
        (SELECT id FROM teams WHERE name LIKE '[CHECK]%' OR leader_id IN
        (SELECT id FROM users WHERE username LIKE 'check_%' OR username LIKE 'chk_reg_%'))""")
    db.execute("""DELETE FROM virtual_keys WHERE key_id IN
        (SELECT id FROM shared_keys WHERE name LIKE '[CHECK]%' OR team_id IN
        (SELECT id FROM teams WHERE name LIKE '[CHECK]%'))""")
    db.execute("""DELETE FROM shared_keys WHERE name LIKE '[CHECK]%' OR team_id IN
        (SELECT id FROM teams WHERE name LIKE '[CHECK]%' OR leader_id IN
        (SELECT id FROM users WHERE username LIKE 'check_%' OR username LIKE 'chk_reg_%'))""")
    db.execute("""DELETE FROM teams WHERE name LIKE '[CHECK]%' OR leader_id IN
        (SELECT id FROM users WHERE username LIKE 'check_%' OR username LIKE 'chk_reg_%')""")
    db.execute("""DELETE FROM usage_records WHERE user_id IN
        (SELECT id FROM users WHERE username LIKE 'check_%' OR username LIKE 'chk_reg_%')
        OR key_id IN (SELECT id FROM shared_keys WHERE name LIKE '[CHECK]%')""")
    db.commit(); db.close()

cleanup_all()  # 自愈:先扫掉历史孤儿账号再开跑

print(f"═══ 钥盾 KeyShield 端到端自检 {time.strftime('%Y-%m-%d %H:%M:%S')} ═══")
print(f"预置账号: {ADMIN}(管理员) / {TEACH}(教职工),跑完自动清理\n")

# ---- 0. 健康 + 预置账号 ----
try:
    r = urllib.request.urlopen(BASE + "/", timeout=10)  # nosec B310 - 固定本机自检地址
    check("1. 官网首页可访问(HTTP 200)", r.status == 200, f"HTTP {r.status}")
except Exception as e:
    check("1. 官网首页可访问", False, str(e)); sys.exit(1)

import datetime
from werkzeug.security import generate_password_hash
def seed_user(name, role):
    db = sqlite3.connect(DB)
    salt = os.urandom(16)
    cur = db.execute("INSERT INTO users(username,pw_hash,salt,role,created) VALUES(?,?,?,?,?)",
                     (name, generate_password_hash(PWD), salt, role,
                      datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    db.commit(); uid = cur.lastrowid; db.close()
    return uid
uid_admin = seed_user(ADMIN, "admin")
uid_teach = seed_user(TEACH, "user")
uid_res = seed_user(RES, "user")
check("2. 数据库预置自检账号(adm/test/res)", uid_admin > 0 and uid_teach > 0 and uid_res > 0)

# ---- 3. 注册接口(不依赖首个账号) ----
tmp, _ = mk()
reg_email = f"chk_reg_{ts}@example.test"
code_resp = req(tmp, "/api/email/send", {"email": reg_email, "purpose": "register"}, "POST")
d = req(tmp, "/api/register", {"username": f"chk_reg_{ts}", "email": reg_email,
    "email_code": code_resp.get("demo_code"), "password": PWD}, "POST")
recovery_key = d.get("recovery_key", "")
me_after_register = req(tmp, "/api/me")
db_check = sqlite3.connect(DB)
new_row = db_check.execute("""SELECT wrapped_key,recovery_wrapped_key,email,email_verified
    FROM users WHERE username=?""", (f"chk_reg_{ts}",)).fetchone()
db_check.close()
check("3. 邮箱验证码注册、双重包装 DEK 并自动登录", d.get("ok") and d.get("role") == "user"
      and me_after_register.get("ok") and bool(new_row[0]) and bool(new_row[1])
      and new_row[2] == reg_email and new_row[3] == 1 and recovery_key.startswith("KS-REC-"), d.get("err", ""))
check("3A. 恢复密钥明文不入库", recovery_key not in str(new_row))
email_login, _ = mk()
d_email_login = req(email_login, "/api/login", {"username": reg_email, "password": PWD}, "POST")
check("3B. 已验证邮箱可与密码组合登录", d_email_login.get("ok"), d_email_login.get("err", ""))
recover_client, _ = mk()
reset_code = req(recover_client, "/api/email/send", {"email": reg_email, "purpose": "reset"}, "POST").get("demo_code")
new_reg_password = "chk-new-123456"
d_recover = req(recover_client, "/api/password/recover", {"identifier": f"chk_reg_{ts}",
    "email_code": reset_code, "recovery_key": recovery_key, "new_password": new_reg_password}, "POST")
after_recover, _ = mk()
d_after_recover = req(after_recover, "/api/login", {"username": reg_email, "password": new_reg_password}, "POST")
check("3C. 邮箱验证码与恢复密钥共同重置密码且保险箱可解锁",
      d_recover.get("ok") and d_after_recover.get("ok"), d_recover.get("err", ""))
d = req(tmp, "/api/register", {"username": "x", "email": reg_email,
    "email_code": "000000", "password": "123"}, "POST")
check("4. 弱密码被拒绝", not d.get("ok"), d.get("err", ""))

# ---- 登录 ----
admin, _ = mk()
d = req(admin, "/api/login", {"username": ADMIN, "password": PWD}, "POST")
db_check = sqlite3.connect(DB)
legacy_wrapped = db_check.execute("SELECT wrapped_key FROM users WHERE id=?", (uid_admin,)).fetchone()[0]
db_check.close()
check("5. 管理员登录且旧用户完成无损迁移", d.get("ok") and bool(legacy_wrapped), d.get("err", ""))
tch, _ = mk()
d = req(tch, "/api/login", {"username": TEACH, "password": PWD}, "POST")
check("6. 教职工登录", d.get("ok"), d.get("err", ""))
d = req(tch, "/api/login", {"username": TEACH, "password": "wrong"}, "POST")
check("7. 错误密码被拒绝", not d.get("ok"), d.get("err", ""))

# ---- 密钥管理(格式校验) ----
d = req(admin, "/api/entries", {"name": "[CHECK] DeepSeek主用", "cat": "DeepSeek", "value": "sk-ds-check1234567890"}, "POST")
check("8. 添加合法 DeepSeek 密钥", d.get("ok"), d.get("err", ""))
d = req(admin, "/api/entries", {"name": "[CHECK] 火山主用", "cat": "火山引擎", "value": "1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d"}, "POST")
check("9. 添加合法火山引擎(UUID)", d.get("ok"), d.get("err", ""))
d = req(admin, "/api/entries", {"name": "[CHECK] 坏key", "cat": "DeepSeek", "value": "12****3123"}, "POST")
check("10. 非法格式被拦截", not d.get("ok"), d.get("err", ""))
d = req(admin, "/api/entries", {"name": "[CHECK] 高德", "cat": "高德", "value": "0a5a7d7597e83b0b33a10f16e513024a"}, "POST")
check("11. 添加合法高德(32位hex)", d.get("ok"), d.get("err", ""))

# ---- 多用户隔离 ----
d = req(tch, "/api/entries")
check("12. 教职工看不到管理员的密钥", len(d.get("entries", [])) == 0, f"实际{len(d.get('entries',[]))}条")
d = req(tch, "/api/entries", {"name": "[CHECK] 我的个人key", "cat": "其他", "value": "my-personal-secret-1"}, "POST")
check("13. 教职工添加自己的密钥", d.get("ok"), d.get("err", ""))
d = req(tch, "/api/entries")
check("14. 教职工列表只看到自己1条", len(d.get("entries", [])) == 1, str([e["name"] for e in d.get("entries", [])]))

# ---- 托管中心 ----
d = req(admin, "/api/shared", {"name": "[CHECK] 学校统一通义Key", "cat": "通义千问", "value": "sk-tongyi-shared-key-123456", "note": "全体教职工"}, "POST")
check("15. 管理员托管密钥", d.get("ok"), d.get("err", ""))
d = req(admin, "/api/shared", {"name": "[CHECK] 学校统一DeepSeek", "cat": "DeepSeek", "value": "sk-ds-shared-key-123456"}, "POST")
check("16. 管理员托管第2个", d.get("ok"), d.get("err", ""))
d = req(tch, "/api/shared")
sh = d.get("shared", [])
mine = [s for s in sh if s["name"].startswith("[CHECK]")]
check("17. 教职工可见自检托管(打码)", len(mine) == 2 and all("****" in s["mask"] for s in mine), str([(s["name"], s["mask"]) for s in mine]))

# ---- 领用/调用 ----
sid1 = max(s["id"] for s in mine if "通义" in s["name"])
sid2 = max(s["id"] for s in mine if "DeepSeek" in s["name"])
d = req(tch, f"/api/shared/{sid2}/use", {}, "POST")
check("18. 未领用直接调用被拒绝", not d.get("ok") and "领用" in str(d.get("err", "")), d.get("err", ""))
d = req(tch, f"/api/shared/{sid1}/grant", {}, "POST")
check("19. 教职工领用", d.get("ok"), d.get("err", ""))
d = req(tch, f"/api/shared/{sid1}/grant", {}, "POST")
check("20. 重复领用被拒绝", not d.get("ok"), d.get("err", ""))
d = req(tch, f"/api/shared/{sid1}/use", {}, "POST")
check("21. 领用后调用成功且代理不下发密钥", d.get("ok") and "value" not in d, str(d))

# ---- 成员专属虚拟 Key / OpenAI 兼容入口 ----
vk = req(tch, "/api/virtual-keys", {"key_id": sid1, "name": "[CHECK] IDE",
    "days": 1, "daily_limit": 3}, "POST")
virtual_token = vk.get("api_key", "")
check("21A. 成员可创建仅显示一次的 ks_ 虚拟 Key",
      vk.get("ok") and virtual_token.startswith("ks_live_") and bool(vk.get("base_url")), vk.get("err", ""))
db_check = sqlite3.connect(DB)
stored = db_check.execute("SELECT token_hash,token_prefix FROM virtual_keys WHERE id=?",
                          (vk.get("id", -1),)).fetchone()
raw_found = db_check.execute("SELECT 1 FROM virtual_keys WHERE token_hash=?", (virtual_token,)).fetchone()
db_check.close()
check("21B. 数据库只保存虚拟 Key 的摘要与前缀",
      bool(stored) and stored[0] != virtual_token and raw_found is None and stored[1] == virtual_token[:16])
status, models = req_bearer("/v1/models", virtual_token)
check("21C. 标准 Bearer 接口按资源返回模型", status == 200 and models.get("object") == "list", str(models))
status, completion = req_bearer("/v1/chat/completions", virtual_token,
    {"model": "auto", "messages": []}, "POST")
check("21D. OpenAI 兼容调用成功且不下发厂商 Key",
      status == 200 and completion.get("object") == "chat.completion" and "api_key" not in completion,
      str(completion)[:120])
status, invalid = req_bearer("/v1/models", "ks_live_invalid")
check("21E. 伪造虚拟 Key 被拒绝", status == 401 and "error" in invalid, str(invalid))
revoked = req(tch, f"/api/virtual-keys/{vk.get('id', -1)}", {}, "DELETE")
status, after_revoke = req_bearer("/v1/models", virtual_token)
check("21F. 撤销后虚拟 Key 立即失效", revoked.get("ok") and status == 401, str(after_revoke))

# ---- 打码/查看/轮换/越权 ----
mine_adm = [e for e in req(admin, "/api/entries")["entries"] if e["name"].startswith("[CHECK]")]
e1 = [e for e in mine_adm if e["name"] == "[CHECK] DeepSeek主用"][0]
check("22. 密钥默认打码", "****" in e1["mask"] and "check1234567890" not in e1["mask"], e1["mask"])
d = req(admin, f"/api/entries/{e1['id']}/reveal", {}, "POST")
check("23. 管理员查看完整值", d.get("ok") and d.get("value") == "sk-ds-check1234567890", d.get("err", ""))
d = req(tch, f"/api/entries/{e1['id']}/reveal", {}, "POST")
check("24. 越权查看他人密钥被拒", not d.get("ok"), d.get("err", ""))
te = req(tch, "/api/entries")["entries"][0]
d = req(tch, f"/api/entries/{te['id']}/rotate", {"value": "sk-rotated-new-key-999"}, "POST")
check("25. 教师轮换密钥", d.get("ok"), d.get("err", ""))
d = req(tch, "/api/entries")
check("26. 轮换后历史+1且打码变化", d["entries"][0]["history_len"] == 1 and "999" in d["entries"][0]["mask"], d["entries"][0]["mask"])
d = req(tch, f"/api/entries/{te['id']}/rotate", {"value": "bad"}, "POST")
check("27. 轮换非法格式被拦截", not d.get("ok"), d.get("err", ""))

# ---- 信封加密改密(数据无需重加密) ----
NEW_PWD = "chk-new-987654"
d = req(tch, "/api/password", {"current_password": PWD, "new_password": NEW_PWD}, "POST")
still_readable = req(tch, f"/api/entries/{te['id']}/reveal", {}, "POST")
old_login, _ = mk(); new_login, _ = mk()
old_rejected = req(old_login, "/api/login", {"username": TEACH, "password": PWD}, "POST")
new_accepted = req(new_login, "/api/login", {"username": TEACH, "password": NEW_PWD}, "POST")
check("27A. 修改密码仅重包装数据密钥且原数据可读", d.get("ok") and
      still_readable.get("value") == "sk-rotated-new-key-999" and
      not old_rejected.get("ok") and new_accepted.get("ok"), d.get("err", ""))

# ---- 审计 ----
tl = req(tch, "/api/logs").get("logs", [])
al = req(admin, "/api/logs").get("logs", [])
check("28. 管理员全站日志多于教职工", len(al) > len(tl), f"教职工{len(tl)}/管理员{len(al)}")
acts = [l["action"] for l in al]
check("29. 全站日志含关键动作", all(a in acts for a in ["领用", "调用", "托管密钥", "登录"]), str(sorted(set(acts))[:12]))
integrity = req(admin, "/api/logs/integrity")
check("29A. 审计日志 HMAC 链与外部锚点校验通过",
      integrity.get("ok") and integrity.get("reason") == "完整性校验通过", str(integrity))

# ---- 用户管理 ----
d = req(admin, "/api/users")
listed_ids = {u["id"] for u in d.get("users", [])}
check("30. 管理员可看用户列表", d.get("ok") and {uid_admin, uid_teach}.issubset(listed_ids), str(len(d.get("users", []))))
reg_user = next(u for u in d.get("users", []) if u["username"] == f"chk_reg_{ts}")
bad_role = req(admin, f"/api/users/{reg_user['id']}/role", {"role":"admin", "current_password":"wrong"}, "POST")
promoted = req(admin, f"/api/users/{reg_user['id']}/role", {"role":"admin", "current_password":PWD}, "POST")
promoted_access = req(after_recover, "/api/users")
demoted = req(admin, f"/api/users/{reg_user['id']}/role", {"role":"user", "current_password":PWD}, "POST")
demoted_access = req(after_recover, "/api/users")
check("30A. 仅现有管理员复核密码后可授权/撤销管理员", not bad_role.get("ok") and promoted.get("ok") and
      promoted_access.get("ok") and demoted.get("ok") and not demoted_access.get("ok"),
      str({"bad":bad_role, "promote":promoted, "access":promoted_access.get("ok"),
           "demote":demoted, "after":demoted_access}))
d = req(tch, "/api/users")
check("31. 教职工访问用户管理被拒", not d.get("ok"), d.get("err", ""))
d = req(admin, f"/api/users/{uid_teach}/toggle", {}, "POST")
check("32. 管理员停用教职工", d.get("ok"), d.get("err", ""))
fresh, _ = mk()
d = req(fresh, "/api/login", {"username": TEACH, "password": PWD}, "POST")
existing_session = req(tch, "/api/me")
check("33. 停用后新旧会话均被拒绝", not d.get("ok") and not existing_session.get("ok"), d.get("err", ""))
d = req(admin, f"/api/users/{uid_teach}/toggle", {}, "POST")
check("34. 管理员恢复教职工", d.get("ok"), d.get("err", ""))

# ---- 校园组织订阅与安全安装包 ----
d = req(admin, "/api/subscription")
check("34A. 校园订阅状态可读取", d.get("ok") and d.get("subscription") is None and
      d.get("contact_email") == "1287585727@qq.com", str(d))
d = req(admin, "/api/subscription/activate-demo", {"plan":"self_hosted"}, "POST")
check("34B. 本地演示订阅开通并解锁安装包", d.get("ok") and
      d.get("subscription", {}).get("status") == "active", d.get("err", ""))
status, headers, payload = req_binary(admin, "/api/subscription/package")
try:
    with zipfile.ZipFile(io.BytesIO(payload)) as package:
        package_names = set(package.namelist())
except zipfile.BadZipFile:
    package_names = set()
forbidden = {"keyshield.db", ".site_key", ".flask_secret"}
check("34C. 安装包白名单完整且不含用户数据/根密钥", status == 200 and
      {"app.py", "templates/index.html", "INSTALLATION-GUIDE.txt"}.issubset(package_names) and
      not (forbidden & package_names) and not any(name.startswith(".venv/") for name in package_names),
      str(sorted(package_names)))

# ---- 演示数据/登出 ----
d = req(admin, "/api/demo", {}, "POST")
check("35. 载入演示数据", d.get("ok"), d.get("err", ""))
d = req(admin, "/api/logout", {}, "POST")
check("36. 登出成功", d.get("ok"), d.get("err", ""))
d = req(admin, "/api/entries")
check("37. 登出后访问被拒(401)", not d.get("ok"), d.get("err", ""))

# ---- 团队系统(班级管控/科研协作,39-48) ----
# 注意:TEACH 在 27A 已改密码为 NEW_PWD;三个会话重新登录,失败即终止(避免连锁报错难排查)
admin, _ = mk(); tch, _ = mk(); res, _ = mk()
for _op, _u, _p in [(admin, ADMIN, PWD), (tch, TEACH, NEW_PWD), (res, RES, PWD)]:
    lg = req(_op, "/api/login", {"username": _u, "password": _p}, "POST")
    if not lg.get("ok"):
        raise RuntimeError(f"团队段重新登录失败: {_u} -> {lg}")

# 39-40 建团
d = req(admin, "/api/teams", {"name": "[CHECK] 班级", "mode": "class"}, "POST")
check("39. 创建班级团队(管控式,生成入队码)", d.get("ok") and str(d.get("join_code", "")).startswith("KS-"), d.get("err", ""))
cid, ccode = d.get("id"), d.get("join_code")
d = req(tch, "/api/teams", {"name": "[CHECK] 课题组", "mode": "research"}, "POST")
check("40. 创建科研团队(协作式)", d.get("ok") and bool(d.get("join_code")), d.get("err", ""))
rid, rcode = d.get("id"), d.get("join_code")

# 41 直加成员带有效期(班级"发卡")
d = req(admin, f"/api/teams/{cid}/members", {"username": TEACH, "expires_at": "2099-01-01"}, "POST")
check("41. 主管理者直加成员并设有效期", d.get("ok"), d.get("err", ""))

# 42 入队码申请 -> 拒绝 -> 重新申请 -> 审核通过(科研团)
d = req(res, "/api/teams/join-by-code", {"join_code": rcode}, "POST")
ok42a = d.get("ok") and d.get("team_id") == rid
d = req(tch, f"/api/teams/{rid}/members/{uid_res}/reject", {}, "POST")
ok42b = d.get("ok")
d = req(res, "/api/teams/join-by-code", {"join_code": rcode}, "POST")
ok42c = d.get("ok")
d = req(tch, f"/api/teams/{rid}/members/{uid_res}/approve", {}, "POST")
check("42. 入队码申请-拒绝-重申请-审核通过", ok42a and ok42b and ok42c and d.get("ok"),
      str({"a": ok42a, "b": ok42b, "c": ok42c, "approve": d}))

# 43 生效班级成员不能添加密钥
d = req(tch, f"/api/teams/{cid}/keys", {"name": "[CHECK] 班级通义", "cat": "通义千问",
    "value": "sk-tongyi-team-1234567890", "model": "qwen-plus"}, "POST")
check("43. 班级成员添加密钥被拒(仅主管理者)", not d.get("ok") and "主管理者" in str(d.get("err", "")), d.get("err", ""))

# 44 主管理者加 key -> 成员领用 -> 代调用成功且不下发
d = req(admin, f"/api/teams/{cid}/keys", {"name": "[CHECK] 班级通义", "cat": "通义千问",
    "value": "sk-tongyi-team-1234567890", "model": "qwen-plus"}, "POST")
ckid = d.get("id")
ok44a = d.get("ok")
d = req(tch, f"/api/teams/{cid}/keys/{ckid}/grant", {}, "POST")
ok44b = d.get("ok")
d = req(tch, f"/api/teams/{cid}/keys/{ckid}/use", {"prompt": ""}, "POST")
check("44. 主管理者添加-成员领用-代调用不下发", ok44a and ok44b and d.get("ok") and "value" not in d, str(d)[:90])

# 45 成员过期后调用被拦截(身份失效)
d = req(admin, f"/api/teams/{cid}/members/{uid_teach}/expiry", {"expires_at": "2000-01-01"}, "POST")
ok45a = d.get("ok")
d = req(tch, f"/api/teams/{cid}/keys/{ckid}/use", {"prompt": ""}, "POST")
check("45. 成员过期后调用被拦截", ok45a and not d.get("ok") and
      ("生效成员" in str(d.get("err", "")) or "过期" in str(d.get("err", ""))), d.get("err", ""))

# 46 科研成员直接添加+调用(无需领用)
d = req(res, f"/api/teams/{rid}/keys", {"name": "[CHECK] 科研DeepSeek", "cat": "DeepSeek",
    "value": "sk-ds-research-team-1234567890", "model": "deepseek-v4-flash"}, "POST")
rkid = d.get("id")
ok46a = d.get("ok")
d = req(res, f"/api/teams/{rid}/keys/{rkid}/use", {"prompt": ""}, "POST")
check("46. 科研成员直接添加并调用(无需领用)", ok46a and d.get("ok") and "value" not in d, str(d)[:90])

# 47 团队用量统计按成员聚合(须在删除密钥之前,删除后该密钥用量不再归属团队)
d = req(tch, f"/api/teams/{rid}/usage", {}, "GET")
check("47. 团队用量统计按成员聚合", d.get("ok") and d["summary"]["calls"] >= 1 and
      any(m["username"] == RES for m in d["members"]), str(d.get("summary")))

# 47A 团队成员提交新 Key 时按“轮换团队密钥”独立审计
d = req(res, f"/api/teams/{rid}/keys/{rkid}",
    {"value": "sk-ds-research-team-rotated-1234567890"}, "PUT")
res_logs = req(res, "/api/logs").get("logs", [])
check("47A. 团队成员轮换 Key 使用独立审计动作", d.get("ok") and
      d.get("action") == "轮换团队密钥" and
      any(log.get("action") == "轮换团队密钥" for log in res_logs), str(d))

# 48 科研成员可编辑删除;非成员越权删除被拒
d = req(res, f"/api/teams/{rid}/keys/{rkid}", {"note": "edited"}, "PUT")
ok48a = d.get("ok")
d = req(admin, f"/api/teams/{rid}/keys/{rkid}", {}, "DELETE")
ok48b = not d.get("ok")
d = req(res, f"/api/teams/{rid}/keys/{rkid}", {}, "DELETE")
check("48. 科研成员可编辑删除,非成员越权被拒", ok48a and ok48b and d.get("ok"), d.get("err", ""))

# ---- 清理自检数据(try/finally 保证即使中途出错也清扫) ----
try:
    cleanup_all()
    check("49. 测试账号/数据已清理(含团队/历史孤儿)", True, "")
except Exception as e:
    check("49. 测试账号/数据已清理(含团队/历史孤儿)", False, str(e))

print(f"\n═══ 自检结果: {PASS} 通过 / {FAIL} 失败 ═══")
sys.exit(1 if FAIL else 0)
