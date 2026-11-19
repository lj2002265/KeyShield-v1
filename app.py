#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
钥盾 KeyShield · 校园AI密钥安全管理平台(服务端版 v3.3)
- 多用户注册/登录,每人独立保险箱
- 密钥经用户密码派生密钥 AES-256-GCM 加密后存储,服务器只存密文
- 管理员:用户管理 / 托管密钥(发卡) / 全站审计
- Flask + SQLite,零外部服务依赖
运行: PYTHONPATH= ./.venv/Scripts/python.exe app.py
"""
import os, json, sqlite3, time, secrets, base64, re, threading, uuid, hmac, io, zipfile
import smtplib, ssl
import urllib.request, urllib.error
from email.message import EmailMessage
from urllib.parse import urlsplit
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps
from hashlib import pbkdf2_hmac, sha256

from flask import Flask, request, jsonify, session, send_from_directory, send_file, g
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

BASE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.abspath(os.environ.get("KEYSHIELD_DATA_DIR", BASE))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.path.join(DATA_DIR, "keyshield.db")
IS_PRODUCTION = os.environ.get("KEYSHIELD_ENV", "development").lower() == "production"
DEMO_MODE = os.environ.get("KEYSHIELD_DEMO_MODE", "0" if IS_PRODUCTION else "1") == "1"
REQUIRE_INVITE = os.environ.get("KEYSHIELD_REQUIRE_INVITE", "0") == "1"
ALLOW_DIRECT_SHARED = os.environ.get("KEYSHIELD_ALLOW_DIRECT", "0" if IS_PRODUCTION else "1") == "1"
DEMO_BILLING = os.environ.get("KEYSHIELD_DEMO_BILLING", "0" if IS_PRODUCTION else "1") == "1"
COOKIE_SECURE = os.environ.get(
    "KEYSHIELD_COOKIE_SECURE", "1" if IS_PRODUCTION else "0"
) == "1"
EMAIL_MODE = os.environ.get("KEYSHIELD_EMAIL_MODE", "demo" if DEMO_MODE else "smtp").lower()
SMTP_HOST = os.environ.get("KEYSHIELD_SMTP_HOST", "").strip()
try:
    SMTP_PORT = max(1, min(int(os.environ.get("KEYSHIELD_SMTP_PORT", "465")), 65535))
except (TypeError, ValueError):
    SMTP_PORT = 465
SMTP_USER = os.environ.get("KEYSHIELD_SMTP_USER", "").strip()
SMTP_PASSWORD = os.environ.get("KEYSHIELD_SMTP_PASSWORD", "")
SMTP_FROM = os.environ.get("KEYSHIELD_SMTP_FROM", SMTP_USER).strip()
SMTP_SSL = os.environ.get("KEYSHIELD_SMTP_SSL", "1") == "1"
SMTP_STARTTLS = os.environ.get("KEYSHIELD_SMTP_STARTTLS", "0" if SMTP_SSL else "1") == "1"
EMAIL_STEP_UP = os.environ.get("KEYSHIELD_EMAIL_STEP_UP", "1" if IS_PRODUCTION else "0") == "1"
EMAIL_READY = EMAIL_MODE == "demo" or bool(SMTP_HOST and SMTP_FROM)

def env_int(name, default, minimum, maximum):
    try:
        return max(minimum, min(int(os.environ.get(name, default)), maximum))
    except (TypeError, ValueError):
        return default

DAILY_CALL_LIMIT = env_int("KEYSHIELD_DAILY_CALL_LIMIT", 100 if IS_PRODUCTION else 1000, 1, 10000)
MAX_OUTPUT_TOKENS = env_int("KEYSHIELD_MAX_OUTPUT_TOKENS", 1024, 64, 4096)
VIRTUAL_KEY_MAX_DAYS = env_int("KEYSHIELD_VIRTUAL_KEY_MAX_DAYS", 90, 1, 365)

def load_session_secret():
    configured = os.environ.get("KEYSHIELD_FLASK_SECRET", "").strip()
    if configured:
        if len(configured) < 32:
            raise RuntimeError("KEYSHIELD_FLASK_SECRET 至少需要32个字符")
        return configured
    path = os.path.join(DATA_DIR, ".flask_secret")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(secrets.token_hex(32))
            f.flush(); os.fsync(f.fileno())
    try: os.chmod(path, 0o600)
    except OSError: pass
    with open(path, "r", encoding="ascii") as f:
        value = f.read().strip()
    if len(value) < 32:
        raise RuntimeError(".flask_secret 内容损坏")
    return value

app = Flask(__name__, static_folder="static", template_folder="templates")
app.secret_key = load_session_secret()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=COOKIE_SECURE,
    MAX_CONTENT_LENGTH=64 * 1024,
    PERMANENT_SESSION_LIFETIME=30 * 60,
)
if os.environ.get("KEYSHIELD_TRUST_PROXY", "0") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# 浏览器 Cookie 只保存不可猜测的会话编号；密码派生密钥仅存在服务端内存。
# 演示版为单进程部署，服务重启后会话自然失效，符合项目原有约定。
SESSION_IDLE_SECONDS = 30 * 60
ACTIVE_SESSIONS = {}  # sid -> {uid, key, last_seen}
SESSION_LOCK = threading.Lock()
SITE_KEY_LOCK = threading.Lock()
_SITE_KEY_CACHE = None
RATE_LIMITS = defaultdict(deque)
RATE_LOCK = threading.Lock()
AUDIT_LOCK = threading.Lock()
AUDIT_ANCHOR_PATH = os.path.join(DATA_DIR, ".audit_anchor")
AUDIT_GENESIS = "0" * 64

def client_ip():
    return request.remote_addr or "unknown"

def rate_limited(bucket, identity, limit, window):
    now = time.time(); key = (bucket, identity)
    with RATE_LOCK:
        q = RATE_LIMITS[key]
        while q and q[0] <= now - window: q.popleft()
        if len(q) >= limit: return True
        q.append(now)
        if len(RATE_LIMITS) > 5000:
            for old_key in list(RATE_LIMITS)[:1000]:
                if not RATE_LIMITS[old_key] or RATE_LIMITS[old_key][-1] <= now - 3600:
                    RATE_LIMITS.pop(old_key, None)
        return False

@app.before_request
def secure_api_request():
    protected_api = request.path.startswith("/api/") or request.path.startswith("/v1/")
    if not protected_api or request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if not request.is_json:
        return jsonify(ok=False, err="请求必须使用 application/json"), 415
    data = request.get_json(silent=True)
    if data is None or not isinstance(data, dict):
        return jsonify(ok=False, err="请求体必须是 JSON 对象"), 400
    origin = request.headers.get("Origin")
    if origin and origin.rstrip("/") != request.host_url.rstrip("/"):
        return jsonify(ok=False, err="跨站请求已拒绝"), 403

@app.after_request
def add_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; connect-src 'self'; object-src 'none'; "
        "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    )
    if IS_PRODUCTION and COOKIE_SECURE and request.is_secure:
        resp.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    if request.path.startswith("/api/") or request.path.startswith("/v1/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

@app.errorhandler(413)
def too_large(_):
    return jsonify(ok=False, err="请求内容过大"), 413

@app.errorhandler(500)
def internal_error(_):
    return jsonify(ok=False, err="服务器内部错误"), 500

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_site_key() -> bytes:
    """加载 32 字节站点密钥。生产环境可用 KEYSHIELD_SITE_KEY 注入 hex/base64。"""
    global _SITE_KEY_CACHE
    with SITE_KEY_LOCK:
        if _SITE_KEY_CACHE is not None:
            return _SITE_KEY_CACHE
        configured = os.environ.get("KEYSHIELD_SITE_KEY", "").strip()
        if configured:
            try:
                key = bytes.fromhex(configured) if re.fullmatch(r"[0-9a-fA-F]{64}", configured) \
                    else base64.b64decode(configured, validate=True)
            except (ValueError, base64.binascii.Error) as exc:
                raise RuntimeError("KEYSHIELD_SITE_KEY 必须是 64 位 hex 或有效 base64") from exc
        else:
            kb = os.path.join(DATA_DIR, ".site_key")
            try:
                fd = os.open(kb, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, "wb") as f:
                    f.write(os.urandom(32))
                    f.flush()
                    os.fsync(f.fileno())
            try:
                os.chmod(kb, 0o600)
            except OSError:
                pass  # Windows 权限由 ACL 管理
            with open(kb, "rb") as f:
                key = f.read()
        if len(key) != 32:
            raise RuntimeError("站点密钥长度错误:必须正好为 32 字节")
        _SITE_KEY_CACHE = key
        return key

def _audit_hash(log_id, user_id, event_time, action, target, detail, prev_hash):
    """HMAC 链：数据库攻击者没有站点密钥时无法重算被修改的历史日志。"""
    payload = json.dumps({
        "id": int(log_id), "user_id": user_id, "time": event_time,
        "action": action or "", "target": target or "", "detail": detail or "",
        "prev_hash": prev_hash or AUDIT_GENESIS,
    }, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(get_site_key(), payload, sha256).hexdigest()

def _anchor_body(count, head_hash, updated=None):
    return {"version": 1, "count": int(count), "head_hash": head_hash,
            "updated": updated or now_str()}

def _anchor_mac(body):
    raw = json.dumps(body, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8")
    return hmac.new(get_site_key(), b"audit-anchor-v1:" + raw, sha256).hexdigest()

def write_audit_anchor(count, head_hash):
    """原子更新数据库外部锚点，用于发现日志尾部被截断。"""
    body = _anchor_body(count, head_hash)
    data = dict(body, mac=_anchor_mac(body))
    tmp_path = AUDIT_ANCHOR_PATH + ".tmp-" + str(os.getpid())
    with open(tmp_path, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        f.flush(); os.fsync(f.fileno())
    try: os.chmod(tmp_path, 0o600)
    except OSError: pass
    os.replace(tmp_path, AUDIT_ANCHOR_PATH)

def read_audit_anchor():
    try:
        with open(AUDIT_ANCHOR_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        body = {k: data[k] for k in ("version", "count", "head_hash", "updated")}
        if not hmac.compare_digest(str(data.get("mac", "")), _anchor_mac(body)):
            return None, "锚点签名无效"
        return data, ""
    except FileNotFoundError:
        return None, "锚点文件不存在"
    except (OSError, ValueError, KeyError, TypeError):
        return None, "锚点文件损坏"

def verify_audit_chain(db=None):
    """验证全部日志的 HMAC 链以及数据库外部锚点。只检查，不自动修复。"""
    own = db is None
    if own:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
    try:
        rows = db.execute("""SELECT id,user_id,time,action,target,detail,prev_hash,event_hash
            FROM logs ORDER BY id""").fetchall()
        prev = AUDIT_GENESIS
        for row in rows:
            if row["prev_hash"] != prev:
                return {"ok": False, "checked": len(rows), "broken_id": row["id"],
                        "reason": "前序哈希不匹配"}
            expected = _audit_hash(row["id"], row["user_id"], row["time"], row["action"],
                                   row["target"], row["detail"], row["prev_hash"])
            if not hmac.compare_digest(row["event_hash"] or "", expected):
                return {"ok": False, "checked": len(rows), "broken_id": row["id"],
                        "reason": "日志内容或哈希被修改"}
            prev = row["event_hash"]
        anchor, anchor_err = read_audit_anchor()
        if not anchor:
            return {"ok": False, "checked": len(rows), "broken_id": None,
                    "reason": anchor_err, "head_hash": prev}
        if int(anchor["count"]) != len(rows) or anchor["head_hash"] != prev:
            return {"ok": False, "checked": len(rows), "broken_id": None,
                    "reason": "日志数量或链头与外部锚点不一致", "head_hash": prev}
        return {"ok": True, "checked": len(rows), "broken_id": None,
                "reason": "完整性校验通过", "head_hash": prev,
                "anchor_updated": anchor["updated"]}
    finally:
        if own: db.close()

def reconcile_unhashed_audit_tail():
    """显式接管旧进程留下的未哈希尾部；已上链内容有任何异常时拒绝修复。"""
    with AUDIT_LOCK:
        db = sqlite3.connect(DB_PATH, timeout=5)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA busy_timeout=5000")
            db.execute("BEGIN IMMEDIATE")
            rows = db.execute("""SELECT id,user_id,time,action,target,detail,prev_hash,event_hash
                FROM logs ORDER BY id""").fetchall()
            anchor, anchor_err = read_audit_anchor()
            if not anchor:
                raise RuntimeError("审计锚点异常:" + anchor_err)
            anchored_count = int(anchor["count"])
            if anchored_count < 0 or anchored_count > len(rows):
                raise RuntimeError("外部锚点计数超出数据库日志范围")

            prev = AUDIT_GENESIS
            for row in rows[:anchored_count]:
                if row["prev_hash"] != prev:
                    raise RuntimeError(f"已锚定审计链在日志 {row['id']} 处断裂")
                expected = _audit_hash(row["id"], row["user_id"], row["time"], row["action"],
                                       row["target"], row["detail"], row["prev_hash"])
                if not hmac.compare_digest(row["event_hash"] or "", expected):
                    raise RuntimeError(f"已锚定审计日志 {row['id']} 内容或哈希被修改")
                prev = row["event_hash"]
            if prev != anchor["head_hash"]:
                raise RuntimeError("已锚定审计链头与外部锚点不一致")

            tail = rows[anchored_count:]
            if any((row["prev_hash"] or row["event_hash"]) for row in tail):
                raise RuntimeError("未锚定尾部包含部分哈希，拒绝自动接管")
            for row in tail:
                digest = _audit_hash(row["id"], row["user_id"], row["time"], row["action"],
                                     row["target"], row["detail"], prev)
                db.execute("UPDATE logs SET prev_hash=?,event_hash=? WHERE id=?",
                           (prev, digest, row["id"]))
                prev = digest
            db.commit()
            write_audit_anchor(len(rows), prev)
            return len(tail)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

def _migrate_audit_chain(db, schema_upgraded=False):
    rows = db.execute("""SELECT id,user_id,time,action,target,detail,prev_hash,event_hash
        FROM logs ORDER BY id""").fetchall()
    hashed = sum(1 for row in rows if row[7])
    if rows and hashed == 0 and schema_upgraded:
        prev = AUDIT_GENESIS
        for row in rows:
            digest = _audit_hash(row[0], row[1], row[2], row[3], row[4], row[5], prev)
            db.execute("UPDATE logs SET prev_hash=?,event_hash=? WHERE id=?", (prev, digest, row[0]))
            prev = digest
        db.commit()
        write_audit_anchor(len(rows), prev)
    elif not rows and not os.path.exists(AUDIT_ANCHOR_PATH):
        write_audit_anchor(0, AUDIT_GENESIS)
    elif rows and hashed == len(rows) and schema_upgraded:
        write_audit_anchor(len(rows), rows[-1][7])

# ---------------- 数据库 ----------------
def get_db():
    db = getattr(g, "_db", None)
    if db is None:
        db = g._db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA busy_timeout=5000")
    return db

@app.teardown_appcontext
def close_db(exc):
    db = getattr(g, "_db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        pw_hash TEXT NOT NULL,
        salt BLOB NOT NULL,
        role TEXT NOT NULL DEFAULT 'user',      -- admin / user
        active INTEGER NOT NULL DEFAULT 1,
        phone TEXT DEFAULT '',
        email TEXT DEFAULT '',
        email_verified INTEGER NOT NULL DEFAULT 0,
        wrapped_key TEXT DEFAULT '', -- 密码派生 KEK 包装的用户数据密钥
        recovery_salt BLOB DEFAULT NULL,
        recovery_wrapped_key TEXT DEFAULT '', -- 恢复密钥派生 KEK 对同一 DEK 的第二份包装
        created TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS entries(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL REFERENCES users(id),
        name TEXT NOT NULL,
        cat TEXT DEFAULT '其他',
        blob TEXT NOT NULL,          -- 加密后的 JSON {value,note,expire,history}
        created TEXT NOT NULL,
        updated TEXT NOT NULL,
        parent INTEGER,              -- 轮换来源(内部)
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS shared_keys(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        cat TEXT DEFAULT '其他',
        blob TEXT NOT NULL,          -- 管理员密钥加密存储
        note TEXT DEFAULT '',
        mode TEXT DEFAULT 'proxy',   -- proxy=仅代调用 / direct=直接下发真key
        model TEXT DEFAULT '',
        created TEXT NOT NULL,
        updated TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS grants(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key_id INTEGER NOT NULL,
        granted_by INTEGER NOT NULL,
        granted_at TEXT NOT NULL,
        status TEXT DEFAULT 'active'
    );
    CREATE TABLE IF NOT EXISTS invitations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        code_hash TEXT UNIQUE NOT NULL,
        created_by INTEGER NOT NULL,
        expires_at REAL NOT NULL,
        max_uses INTEGER NOT NULL DEFAULT 1,
        used_count INTEGER NOT NULL DEFAULT 0,
        active INTEGER NOT NULL DEFAULT 1,
        created TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS usage_records(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        request_id TEXT UNIQUE NOT NULL,
        user_id INTEGER NOT NULL,
        key_id INTEGER NOT NULL,
        provider TEXT NOT NULL,
        model TEXT NOT NULL,
        started TEXT NOT NULL,
        finished TEXT DEFAULT '',
        input_tokens INTEGER DEFAULT 0,
        output_tokens INTEGER DEFAULT 0,
        total_tokens INTEGER DEFAULT 0,
        status TEXT NOT NULL DEFAULT 'pending',
        latency_ms INTEGER DEFAULT 0,
        error_code TEXT DEFAULT '',
        source_ip_hash TEXT DEFAULT '',
        virtual_key_id INTEGER DEFAULT NULL
    );
    CREATE TABLE IF NOT EXISTS logs(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        time TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT DEFAULT '',
        detail TEXT DEFAULT '',
        prev_hash TEXT DEFAULT '',
        event_hash TEXT DEFAULT ''
    );
    CREATE TABLE IF NOT EXISTS teams(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        mode TEXT NOT NULL DEFAULT 'class',     -- class=班级管控 / research=科研协作
        leader_id INTEGER NOT NULL REFERENCES users(id),
        join_code TEXT NOT NULL,
        created TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS team_members(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        team_id INTEGER NOT NULL REFERENCES teams(id),
        user_id INTEGER NOT NULL REFERENCES users(id),
        role TEXT NOT NULL DEFAULT 'member',     -- leader / member
        status TEXT NOT NULL DEFAULT 'pending',  -- pending 待审核 / active 生效 / rejected 已拒绝
        joined_at TEXT NOT NULL,
        expires_at TEXT DEFAULT NULL,            -- 成员有效期 YYYY-MM-DD;NULL=长期
        FOREIGN KEY(team_id) REFERENCES teams(id),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS subscriptions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
        plan TEXT NOT NULL,                     -- self_hosted / assisted
        status TEXT NOT NULL DEFAULT 'active', -- active / cancelled
        started TEXT NOT NULL,
        updated TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS virtual_keys(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        key_id INTEGER NOT NULL,
        name TEXT NOT NULL,
        token_prefix TEXT NOT NULL,
        token_hash TEXT UNIQUE NOT NULL,
        created TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        daily_limit INTEGER NOT NULL,
        active INTEGER NOT NULL DEFAULT 1,
        revoked_at TEXT DEFAULT '',
        last_used_at TEXT DEFAULT ''
    );
    """)
    # 兼容旧库:users 表缺 phone 列时补充
    cols = [r[1] for r in db.execute("PRAGMA table_info(users)").fetchall()]
    if "phone" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN phone TEXT DEFAULT ''")
    if "wrapped_key" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN wrapped_key TEXT DEFAULT ''")
    if "email" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
    if "email_verified" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 0")
    if "recovery_salt" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN recovery_salt BLOB DEFAULT NULL")
    if "recovery_wrapped_key" not in cols:
        db.execute("ALTER TABLE users ADD COLUMN recovery_wrapped_key TEXT DEFAULT ''")
    # 兼容旧库:shared_keys 表缺 mode 列时补充
    scols = [r[1] for r in db.execute("PRAGMA table_info(shared_keys)").fetchall()]
    if "mode" not in scols:
        db.execute("ALTER TABLE shared_keys ADD COLUMN mode TEXT DEFAULT 'proxy'")
    if "model" not in scols:
        db.execute("ALTER TABLE shared_keys ADD COLUMN model TEXT DEFAULT ''")
    if "team_id" not in scols:
        # 兼容旧库:shared_keys 增加 team_id(NULL=学校全局池,保持管理员发卡流程不变)
        db.execute("ALTER TABLE shared_keys ADD COLUMN team_id INTEGER DEFAULT NULL")
    ucols = [r[1] for r in db.execute("PRAGMA table_info(usage_records)").fetchall()]
    if "virtual_key_id" not in ucols:
        db.execute("ALTER TABLE usage_records ADD COLUMN virtual_key_id INTEGER DEFAULT NULL")
    lcols = [r[1] for r in db.execute("PRAGMA table_info(logs)").fetchall()]
    audit_schema_upgraded = False
    if "prev_hash" not in lcols:
        db.execute("ALTER TABLE logs ADD COLUMN prev_hash TEXT DEFAULT ''")
        audit_schema_upgraded = True
    if "event_hash" not in lcols:
        db.execute("ALTER TABLE logs ADD COLUMN event_hash TEXT DEFAULT ''")
        audit_schema_upgraded = True
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_teams_join_code ON teams(join_code)")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_team_members_team_user ON team_members(team_id,user_id)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_team_members_user ON team_members(user_id)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_team_members_team ON team_members(team_id)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_shared_keys_team ON shared_keys(team_id)")
    # 历史重复领用保留最新一条,随后用唯一索引从数据库层阻止并发重复。
    db.execute("""DELETE FROM grants WHERE id NOT IN
        (SELECT MAX(id) FROM grants GROUP BY user_id,key_id)""")
    db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_grants_user_key ON grants(user_id,key_id)")
    duplicate_phone = db.execute("""SELECT phone FROM users WHERE phone<>''
        GROUP BY phone HAVING COUNT(*)>1 LIMIT 1""").fetchone()
    if not duplicate_phone:
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_phone ON users(phone) WHERE phone<>''")
    duplicate_email = db.execute("""SELECT lower(email) FROM users WHERE email<>''
        GROUP BY lower(email) HAVING COUNT(*)>1 LIMIT 1""").fetchone()
    if not duplicate_email:
        db.execute("""CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email
            ON users(email COLLATE NOCASE) WHERE email<>''""")
    db.execute("CREATE INDEX IF NOT EXISTS ix_usage_user_started ON usage_records(user_id,started)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_usage_key_started ON usage_records(key_id,started)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_logs_user_id ON logs(user_id,id DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_subscriptions_status ON subscriptions(status)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_virtual_keys_user ON virtual_keys(user_id,id DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_virtual_keys_resource ON virtual_keys(key_id,active)")
    db.execute("CREATE INDEX IF NOT EXISTS ix_usage_virtual_started ON usage_records(virtual_key_id,started)")
    db.execute("PRAGMA optimize")
    db.commit()
    _migrate_audit_chain(db, audit_schema_upgraded)
    db.close()

# 无论由 Flask 开发服务器还是 Waitress 导入,都保证表结构存在。
init_db()

# ---------------- 密码学 ----------------
def derive_key(password: str, salt: bytes) -> bytes:
    """PBKDF2-SHA256 派生 32 字节 AES-256 密钥(24万次迭代)"""
    return pbkdf2_hmac("sha256", password.encode(), salt, 240000, dklen=32)

def aes_encrypt(key: bytes, plaintext: str) -> str:
    """服务器端复用 Python 自带能力太弱;这里用 AES-GCM 需要 cryptography。
    为减少依赖,采用 pycryptodomex 不可用时回退 otp? 简化:直接用 hashlib+hmac 构建流式加密不可行。
    故这里内嵌一个基于标准库的 AES-CBC 实现过重——直接声明依赖 cryptography(requirements 已装)。
    """
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    enc = cipher.encryptor()
    ct = enc.update(plaintext.encode()) + enc.finalize()
    return json.dumps({"iv": base64.b64encode(iv).decode(),
                       "ct": base64.b64encode(ct).decode(),
                       "tag": base64.b64encode(enc.tag).decode()})

def aes_decrypt(key: bytes, blob: str) -> str:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    d = json.loads(blob)
    iv = base64.b64decode(d["iv"]); ct = base64.b64decode(d["ct"]); tag = base64.b64decode(d["tag"])
    dec = Cipher(algorithms.AES(key), modes.GCM(iv, tag)).decryptor()
    return (dec.update(ct) + dec.finalize()).decode()

def build_user_key_material(password):
    """为新用户生成独立 DEK,并使用密码派生 KEK 包装。"""
    salt = os.urandom(16)
    data_key = os.urandom(32)
    wrapped_key = aes_encrypt(derive_key(password, salt), base64.b64encode(data_key).decode())
    return salt, data_key, wrapped_key

def normalize_recovery_key(value):
    return re.sub(r"[^A-Z2-7]", "", (value or "").upper())

def build_recovery_material(data_key):
    """生成只显示一次的高熵恢复密钥，并用它对同一用户 DEK 做第二份包装。"""
    raw = base64.b32encode(os.urandom(32)).decode("ascii").rstrip("=")
    recovery_key = "KS-REC-" + "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))
    recovery_salt = os.urandom(16)
    recovery_kek = derive_key(normalize_recovery_key(recovery_key), recovery_salt)
    recovery_wrapped = aes_encrypt(recovery_kek, base64.b64encode(data_key).decode())
    return recovery_key, recovery_salt, recovery_wrapped

def unwrap_with_recovery_key(user, recovery_key):
    if not user["recovery_salt"] or not user["recovery_wrapped_key"]:
        raise RuntimeError("账号尚未启用恢复密钥")
    recovery_kek = derive_key(normalize_recovery_key(recovery_key), bytes(user["recovery_salt"]))
    try:
        data_key = base64.b64decode(
            aes_decrypt(recovery_kek, user["recovery_wrapped_key"]), validate=True
        )
    except Exception as exc:
        raise RuntimeError("恢复密钥错误") from exc
    if len(data_key) != 32:
        raise RuntimeError("恢复密钥错误")
    return data_key

def get_user_data_key(user, password, db):
    """解包用户数据密钥；旧用户首次登录时无损迁移为信封加密。"""
    kek = derive_key(password, bytes(user["salt"]))
    if user["wrapped_key"]:
        try:
            data_key = base64.b64decode(aes_decrypt(kek, user["wrapped_key"]), validate=True)
        except Exception as exc:
            raise RuntimeError("用户数据密钥解包失败") from exc
        if len(data_key) != 32:
            raise RuntimeError("用户数据密钥长度错误")
        return data_key
    # 旧版密文直接使用密码派生密钥；把该密钥包装后即可兼容原密文。
    data_key = kek
    wrapped = aes_encrypt(kek, base64.b64encode(data_key).decode())
    db.execute("UPDATE users SET wrapped_key=? WHERE id=?", (wrapped, user["id"]))
    db.commit()
    return data_key

def start_session(uid, data_key):
    sid = secrets.token_urlsafe(32)
    now = time.time()
    with SESSION_LOCK:
        # 清理过期会话，并限制单个账号同时最多保留 5 个会话。
        expired = [old_sid for old_sid, rec in ACTIVE_SESSIONS.items()
                   if now - rec["last_seen"] > SESSION_IDLE_SECONDS]
        for old_sid in expired:
            ACTIVE_SESSIONS.pop(old_sid, None)
        same_user = sorted(
            ((old_sid, rec["last_seen"]) for old_sid, rec in ACTIVE_SESSIONS.items()
             if rec["uid"] == uid), key=lambda item: item[1]
        )
        for old_sid, _ in same_user[:-4]:
            ACTIVE_SESSIONS.pop(old_sid, None)
        ACTIVE_SESSIONS[sid] = {
            "uid": uid,
            "key": data_key,
            "last_seen": now,
        }
    session.clear()
    session.permanent = True
    session["sid"] = sid
    session["uid"] = uid

def end_session():
    sid = session.get("sid")
    if sid:
        with SESSION_LOCK:
            ACTIVE_SESSIONS.pop(sid, None)
    session.clear()

def revoke_other_sessions(uid, keep_sid=None):
    with SESSION_LOCK:
        stale = [sid for sid, rec in ACTIVE_SESSIONS.items()
                 if rec["uid"] == uid and sid != keep_sid]
        for sid in stale:
            ACTIVE_SESSIONS.pop(sid, None)

def current_session():
    sid = session.get("sid")
    if not sid:
        return None
    now = time.time()
    with SESSION_LOCK:
        rec = ACTIVE_SESSIONS.get(sid)
        if not rec or rec["uid"] != session.get("uid") or now - rec["last_seen"] > SESSION_IDLE_SECONDS:
            ACTIVE_SESSIONS.pop(sid, None)
            return None
        rec["last_seen"] = now
        return rec

def user_crypto_key(user=None):
    rec = current_session()
    if not rec:
        raise RuntimeError("登录会话已失效")
    return rec["key"]

# ---------------- 认证 ----------------
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        rec = current_session()
        if not rec:
            session.clear()
            return jsonify(ok=False, err="未登录"), 401
        uid = rec["uid"]
        u = get_db().execute("SELECT active FROM users WHERE id=?", (uid,)).fetchone()
        if not u or not u["active"]:
            end_session()
            return jsonify(ok=False, err="账号已被停用,请联系管理员"), 401
        return f(*a, **k)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **k):
        rec = current_session()
        if not rec:
            session.clear()
            return jsonify(ok=False, err="未登录"), 401
        uid = rec["uid"]
        db = get_db()
        u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
        if not u or not u["active"]:
            end_session()
            return jsonify(ok=False, err="账号已被停用,请联系管理员"), 401
        if u["role"] != "admin":
            return jsonify(ok=False, err="需要管理员权限"), 403
        return f(*a, **k)
    return w

def add_log(uid, action, target="", detail=""):
    """追加HMAC链式审计日志；不允许在完整性锚点异常时继续覆盖证据。"""
    with AUDIT_LOCK:
        db = sqlite3.connect(DB_PATH, timeout=5)
        try:
            db.execute("PRAGMA busy_timeout=5000")
            db.execute("BEGIN IMMEDIATE")
            count, prev = db.execute(
                "SELECT COUNT(*),COALESCE((SELECT event_hash FROM logs ORDER BY id DESC LIMIT 1),?) FROM logs",
                (AUDIT_GENESIS,)).fetchone()
            anchor, anchor_err = read_audit_anchor()
            if not anchor:
                if count == 0:
                    write_audit_anchor(0, AUDIT_GENESIS)
                    anchor = {"count": 0, "head_hash": AUDIT_GENESIS}
                else:
                    raise RuntimeError("审计锚点异常:" + anchor_err)
            if int(anchor["count"]) != count or anchor["head_hash"] != prev:
                raise RuntimeError("审计链与外部锚点不一致，拒绝追加日志")
            event_time = now_str()
            cur = db.execute("""INSERT INTO logs(user_id,time,action,target,detail,prev_hash,event_hash)
                VALUES(?,?,?,?,?,?,?)""", (uid, event_time, action, target, detail, prev, ""))
            digest = _audit_hash(cur.lastrowid, uid, event_time, action, target, detail, prev)
            db.execute("UPDATE logs SET event_hash=? WHERE id=?", (digest, cur.lastrowid))
            db.commit()
            write_audit_anchor(count + 1, digest)
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

def mask_val(v):
    if not v or len(v) < 8:
        return (v[:1] + "****") if v else ""
    head = v[:4] if len(v) >= 14 else v[:2]
    return head + "****" + v[-4:]

def invite_hash(code):
    return sha256((code or "").strip().upper().encode("utf-8")).hexdigest()

def ip_fingerprint():
    """只保存不可逆的来源标识，避免审计表长期留存明文 IP。"""
    return hmac.new(get_site_key(), client_ip().encode("utf-8"), sha256).hexdigest()[:20]

def clean_text(value, max_len):
    return str(value or "").strip()[:max_len]

# ---------------- 密钥格式校验(与前端同规则) ----------------
import re as _re
KEY_RULES = {
    "OpenAI":     lambda s: bool(_re.match(r"^sk-[A-Za-z0-9_\-]{20,}$", s)),
    "DeepSeek":   lambda s: bool(_re.match(r"^sk-[A-Za-z0-9_\-]{16,}$", s)),
    "Kimi":       lambda s: bool(_re.match(r"^sk-[A-Za-z0-9_\-]{16,}$", s)),
    "通义千问":   lambda s: bool(_re.match(r"^sk-[A-Za-z0-9_\-]{16,}$", s)),
    "MiniMax":    lambda s: bool(_re.match(r"^[A-Za-z0-9_\-]{20,}$", s)),
    "硅基流动":   lambda s: bool(_re.match(r"^sk-[A-Za-z0-9_\-]{16,}$", s)),
    "Claude":     lambda s: bool(_re.match(r"^sk-ant-[A-Za-z0-9_\-]{20,}$", s)),
    "Gemini":     lambda s: bool(_re.match(r"^AIzaSy[A-Za-z0-9_\-]{25,}$", s)),
    "火山引擎":   lambda s: bool(_re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$", s)) or bool(_re.match(r"^[A-Za-z0-9_\-]{32,}$", s)),
    "智谱清言":   lambda s: bool(_re.match(r"^[A-Za-z0-9]{16,32}\.[A-Za-z0-9]{16,32}$", s)),
    "高德":       lambda s: bool(_re.match(r"^[0-9a-fA-F]{32}$", s)),
    "百度地图":   lambda s: bool(_re.match(r"^[A-Za-z0-9]{24,}$", s)) and not _re.search(r"\s", s),
    "腾讯地图":   lambda s: bool(_re.match(r"^[A-Za-z0-9]{24,}$", s)) and not _re.search(r"\s", s),
    "君道AI":     lambda s: len(s) >= 16 and not _re.search(r"\s", s),
    "Ollama":     lambda s: len(s) >= 8 and not _re.search(r"\s", s),
    "校园服务":   lambda s: len(s) >= 8 and not _re.search(r"\s", s),
    "其他":       lambda s: len(s) >= 8 and not _re.search(r"\s", s),
}
KEY_RULE_HINTS = {
    "OpenAI": "OpenAI 的 key 以 sk- 开头,后面至少 20 位(如 sk-proj-xxxx...)",
    "DeepSeek": "DeepSeek 的 key 以 sk- 开头,后面至少 16 位字母/数字",
    "Kimi": "Kimi(月之暗面)的 key 以 sk- 开头,后面至少 16 位",
    "通义千问": "通义千问(阿里百炼)的 key 以 sk- 开头,后面至少 16 位",
    "MiniMax": "MiniMax 的 key 至少 20 位,且不含空格",
    "硅基流动": "硅基流动的 key 以 sk- 开头,后面至少 16 位",
    "Claude": "Claude(Anthropic)的 key 以 sk-ant- 开头,后面至少 20 位",
    "Gemini": "Gemini 的 key 以 AIzaSy 开头(示例:AIzaSyxxxxxxxx...)",
    "火山引擎": "火山引擎(方舟)的 key 是 UUID 格式(8-4-4-4-12,如 1a2b3c4d-xxxx-xxxx-xxxx-xxxxxxxxxxxx)",
    "智谱清言": "智谱(GLM)的 key 是 id.secret 两段式,用点分隔",
    "高德": "高德 key 是 32 位十六进制字符(0-9/a-f)",
    "百度地图": "百度地图的 ak 至少 24 位,且不含空格",
    "腾讯地图": "腾讯地图的 key 至少 24 位,且不含空格",
    "君道AI": "君道AI token 至少 16 位且不含空格",
    "Ollama": "至少 8 位且不含空格",
    "校园服务": "至少 8 位且不含空格",
    "其他": "至少 8 位且不含空格",
}
def validate_key_format(cat, value):
    rule = KEY_RULES.get(cat, KEY_RULES["其他"])
    if not rule(value):
        return KEY_RULE_HINTS.get(cat, KEY_RULE_HINTS["其他"])
    return None

# ---------------- 静态页 ----------------
@app.route("/")
def index():
    return send_from_directory(app.template_folder, "index.html")

@app.route("/favicon.ico")
def favicon():
    return "", 204

@app.route("/api/public-config")
def public_config():
    return jsonify(ok=True, invite_required=REQUIRE_INVITE, demo_mode=DEMO_MODE,
                   direct_mode=ALLOW_DIRECT_SHARED, email_ready=EMAIL_READY,
                   email_demo=EMAIL_MODE == "demo", email_step_up=EMAIL_STEP_UP,
                   environment="production" if IS_PRODUCTION else "development")

@app.route("/api/health")
def health():
    try:
        get_db().execute("SELECT 1").fetchone()
        return jsonify(ok=True, status="healthy", database="ok")
    except sqlite3.Error:
        return jsonify(ok=False, status="unhealthy", database="error"), 503

# ---------------- 校园组织订阅与安装包交付 ----------------
CAMPUS_CONTACT_EMAIL = "1287585727@qq.com"
CAMPUS_PLANS = {
    "self_hosted": "安装包本地部署",
    "assisted": "协助部署",
}

@app.route("/api/subscription", methods=["GET"])
@login_required
def subscription_status():
    row = get_db().execute("""SELECT plan,status,started,updated FROM subscriptions
        WHERE user_id=?""", (session["uid"],)).fetchone()
    return jsonify(
        ok=True,
        subscription=dict(row) if row else None,
        billing_mode="demo" if DEMO_BILLING else "contact",
        contact_email=CAMPUS_CONTACT_EMAIL,
        plans=[{"id": key, "name": value} for key, value in CAMPUS_PLANS.items()],
    )

@app.route("/api/subscription/activate-demo", methods=["POST"])
@login_required
def activate_demo_subscription():
    if not DEMO_BILLING:
        return jsonify(ok=False, err="正式环境需联系服务方确认订阅"), 403
    d = request.get_json(silent=True) or {}
    plan = clean_text(d.get("plan"), 32)
    if plan not in CAMPUS_PLANS:
        return jsonify(ok=False, err="请选择有效的部署方式"), 400
    if rate_limited("subscription", str(session["uid"]), 10, 600):
        return jsonify(ok=False, err="操作过于频繁，请稍后再试"), 429
    db = get_db()
    now = now_str()
    db.execute("""INSERT INTO subscriptions(user_id,plan,status,started,updated)
        VALUES(?,?,'active',?,?)
        ON CONFLICT(user_id) DO UPDATE SET
            plan=excluded.plan,status='active',updated=excluded.updated""",
        (session["uid"], plan, now, now))
    db.commit()
    add_log(session["uid"], "演示订阅开通", CAMPUS_PLANS[plan], "本地演示，不产生费用")
    row = db.execute("""SELECT plan,status,started,updated FROM subscriptions
        WHERE user_id=?""", (session["uid"],)).fetchone()
    return jsonify(ok=True, subscription=dict(row), msg="演示订阅已开通，安装包已解锁")

def build_campus_package():
    """只按固定白名单打包代码；数据库、站点密钥和运行环境永不进入交付包。"""
    package_files = (
        "app.py",
        "admin_setup.py",
        "requirements.txt",
        "templates/index.html",
        "deploy/deploy.sh",
        "deploy/backup.sh",
        "README.md",
        "production_check.py",
        "self_check.py",
    )
    guide = f"""钥盾 KeyShield · 校园本地部署安装包

交付内容
1. app.py 与 templates/index.html：服务端和网页界面。
2. requirements.txt：Python 依赖。
3. deploy/deploy.sh：Ubuntu/Debian + Nginx + HTTPS 自动部署脚本。
4. admin_setup.py：在服务器终端安全初始化首个管理员。
5. production_check.py / self_check.py：部署前安全检查与业务回归。

重要安全说明
- 此安装包不包含任何用户数据库、API Key、.site_key、.flask_secret 或虚拟环境。
- 正式部署请设置 KEYSHIELD_ENV=production 和 KEYSHIELD_DEMO_BILLING=0。
- 请只开放 80/443，不要把应用端口 8800 直接暴露到公网。
- 数据库、.site_key 与 .flask_secret 应按 README 的说明备份和保护。

需要协助部署，请联系：{CAMPUS_CONTACT_EMAIL}
"""
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for relative_path in package_files:
            source_path = os.path.join(BASE, *relative_path.split("/"))
            if os.path.isfile(source_path):
                archive.write(source_path, arcname=relative_path)
        archive.writestr("INSTALLATION-GUIDE.txt", guide.encode("utf-8"))
    stream.seek(0)
    return stream

@app.route("/api/subscription/package", methods=["GET"])
@login_required
def download_campus_package():
    row = get_db().execute("""SELECT plan FROM subscriptions
        WHERE user_id=? AND status='active'""", (session["uid"],)).fetchone()
    if not row:
        return jsonify(ok=False, err="订阅生效后才能下载安装包"), 403
    add_log(session["uid"], "下载安装包", CAMPUS_PLANS.get(row["plan"], row["plan"]), "安全白名单交付")
    return send_file(
        build_campus_package(),
        mimetype="application/zip",
        as_attachment=True,
        download_name="KeyShield-campus-self-hosted.zip",
        max_age=0,
    )

# ---------------- 邮箱验证码与账号恢复 ----------------
EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")
EMAIL_CODES = {}  # (purpose,email) -> {digest,expires,attempts}
EMAIL_CODE_LOCK = threading.Lock()
EMAIL_PURPOSES = {
    "register": "注册钥盾账号",
    "reset": "重置钥盾密码",
    "bind": "绑定钥盾邮箱",
    "stepup": "确认敏感操作",
}

def normalize_email(value):
    return (value or "").strip().lower()

def mask_email(value):
    email = normalize_email(value)
    if "@" not in email:
        return "未绑定邮箱"
    name, domain = email.split("@", 1)
    shown = name[:2] if len(name) > 2 else name[:1]
    return shown + "***@" + domain

def email_code_digest(purpose, email, code):
    payload = f"email-code:{purpose}:{normalize_email(email)}:{code}".encode("utf-8")
    return hmac.new(get_site_key(), payload, sha256).hexdigest()

def store_email_code(purpose, email, code):
    with EMAIL_CODE_LOCK:
        EMAIL_CODES[(purpose, normalize_email(email))] = {
            "digest": email_code_digest(purpose, email, code),
            "expires": time.time() + 600,
            "attempts": 0,
        }

def verify_email_code(purpose, email, code, consume=True):
    key = (purpose, normalize_email(email))
    with EMAIL_CODE_LOCK:
        rec = EMAIL_CODES.get(key)
        if not rec:
            return False, "请先获取邮箱验证码"
        if time.time() > rec["expires"]:
            EMAIL_CODES.pop(key, None)
            return False, "邮箱验证码已过期，请重新获取"
        rec["attempts"] += 1
        valid = hmac.compare_digest(rec["digest"], email_code_digest(purpose, email, (code or "").strip()))
        if not valid:
            if rec["attempts"] >= 5:
                EMAIL_CODES.pop(key, None)
                return False, "验证码错误次数过多，请重新获取"
            return False, "邮箱验证码错误"
        if consume:
            EMAIL_CODES.pop(key, None)
        return True, None

def deliver_email_code(email, code, purpose):
    if EMAIL_MODE == "demo":
        return True
    if not EMAIL_READY:
        return False
    msg = EmailMessage()
    msg["Subject"] = f"钥盾 KeyShield · {EMAIL_PURPOSES[purpose]}验证码"
    msg["From"] = SMTP_FROM
    msg["To"] = email
    msg.set_content(
        f"你的钥盾验证码是：{code}\n\n"
        "验证码 10 分钟内有效，最多可尝试 5 次。\n"
        "如果不是你本人操作，请忽略此邮件，不要向任何人提供验证码。"
    )
    context = ssl.create_default_context()
    try:
        if SMTP_SSL:
            with smtplib.SMTP_SSL(SMTP_HOST, SMTP_PORT, timeout=10, context=context) as client:
                if SMTP_USER:
                    client.login(SMTP_USER, SMTP_PASSWORD)
                client.send_message(msg)
        else:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as client:
                client.ehlo()
                if SMTP_STARTTLS:
                    client.starttls(context=context)
                    client.ehlo()
                if SMTP_USER:
                    client.login(SMTP_USER, SMTP_PASSWORD)
                client.send_message(msg)
        return True
    except (OSError, smtplib.SMTPException):
        return False

@app.route("/api/email/send", methods=["POST"])
def send_email_code_api():
    d = request.get_json(silent=True) or {}
    purpose = clean_text(d.get("purpose"), 16)
    email = normalize_email(d.get("email"))
    if purpose not in EMAIL_PURPOSES:
        return jsonify(ok=False, err="验证码用途无效"), 400
    if not EMAIL_READY:
        return jsonify(ok=False, err="邮件服务尚未配置，请联系管理员"), 503
    db = get_db()
    current = current_session()
    if purpose == "stepup" and current:
        stepup_user = db.execute("SELECT * FROM users WHERE id=?", (current["uid"],)).fetchone()
        email = normalize_email(stepup_user["email"] if stepup_user else "")
    if not EMAIL_RE.fullmatch(email) or len(email) > 254:
        return jsonify(ok=False, err="邮箱格式不正确"), 400
    if rate_limited("email-ip", client_ip(), 10, 600) or rate_limited("email-address", email, 3, 600):
        return jsonify(ok=False, err="验证码请求过于频繁，请稍后再试"), 429

    user = None
    if purpose in ("bind", "stepup"):
        if not current:
            return jsonify(ok=False, err="未登录"), 401
        user = db.execute("SELECT * FROM users WHERE id=?", (current["uid"],)).fetchone()
        if purpose == "stepup":
            if not user["email_verified"] or normalize_email(user["email"]) != email:
                return jsonify(ok=False, err="请先绑定并验证账号邮箱"), 403
        elif db.execute("SELECT 1 FROM users WHERE lower(email)=lower(?) AND id<>?", (email, user["id"])).fetchone():
            return jsonify(ok=False, err="该邮箱已绑定其他账号"), 409
    elif purpose == "register":
        if db.execute("SELECT 1 FROM users WHERE lower(email)=lower(?)", (email,)).fetchone():
            return jsonify(ok=False, err="该邮箱已注册"), 409
    else:  # reset：无论账号是否存在都返回相同结果，避免枚举注册邮箱。
        user = db.execute("SELECT * FROM users WHERE lower(email)=lower(?) AND email_verified=1", (email,)).fetchone()
        if not user:
            return jsonify(ok=True, msg="如果该邮箱已绑定，验证码将发送到邮箱")

    code = f"{secrets.randbelow(1000000):06d}"
    if not deliver_email_code(email, code, purpose):
        return jsonify(ok=False, err="验证码邮件发送失败，请稍后重试"), 503
    store_email_code(purpose, email, code)
    uid = user["id"] if user else None
    add_log(uid, "邮箱验证码", mask_email(email), EMAIL_PURPOSES[purpose] + "（未记录验证码）")
    result = {"ok": True, "msg": "验证码已发送到邮箱"}
    if EMAIL_MODE == "demo":
        result["demo_code"] = code
    return jsonify(**result)

# ---------------- 短信验证码(旧版演示兼容) ----------------
SMS_STORE = {}  # phone -> {"code": "123456", "expires": timestamp}
PHONE_RE = re.compile(r"^1[3-9]\d{9}$")

def sms_send(phone):
    """发送短信验证码。演示模式:验证码直接返回给前端展示。
    正式部署:将此处替换为阿里云/腾讯云短信 API(见 README 说明)。"""
    if not PHONE_RE.match(phone):
        return None, "手机号格式不正确(应为 1 开头的 11 位号)"
    code = f"{secrets.randbelow(1000000):06d}"
    SMS_STORE[phone] = {"code": code, "expires": time.time() + 300}
    return code, None

@app.route("/api/sms/send", methods=["POST"])
def sms_send_api():
    d = request.get_json(silent=True) or {}
    phone = (d.get("phone") or "").strip()
    if not DEMO_MODE:
        return jsonify(ok=False, err="公网环境已关闭演示验证码，请使用管理员发放的邀请码注册"), 503
    if rate_limited("sms-ip", client_ip(), 8, 600) or rate_limited("sms-phone", phone, 3, 600):
        return jsonify(ok=False, err="验证码请求过于频繁，请稍后再试"), 429
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE phone=?", (phone,)).fetchone():
        return jsonify(ok=False, err="该手机号已绑定其他账号", demo_code=None)
    code, err = sms_send(phone)
    if err:
        return jsonify(ok=False, err=err)
    add_log(None, "短信验证码", "手机号尾号" + phone[-4:] if len(phone) >= 4 else "无效手机号",
            "演示模式:验证码已生成(未接真实短信通道)")
    return jsonify(ok=True, msg="验证码已发送(演示模式直接显示)", demo_code=code)

def sms_verify(phone, code):
    rec = SMS_STORE.get(phone)
    if not rec:
        return False, "请先获取验证码"
    if time.time() > rec["expires"]:
        return False, "验证码已过期,请重新获取"
    if rec["code"] != (code or "").strip():
        return False, "验证码错误"
    SMS_STORE.pop(phone, None)
    return True, None

# ---------------- 认证 API ----------------
@app.route("/api/register", methods=["POST"])
def register():
    d = request.get_json(silent=True) or {}
    u = clean_text(d.get("username"), 50)
    p = d.get("password") or ""
    email = normalize_email(d.get("email"))
    code = (d.get("email_code") or "").strip()
    invitation = clean_text(d.get("invitation"), 128)
    if rate_limited("register", client_ip(), 8, 600):
        return jsonify(ok=False, err="注册请求过于频繁，请稍后再试"), 429
    if len(u) < 2 or len(p) < 8 or len(p) > 128:
        return jsonify(ok=False, err="用户名需2-50位，密码需8-128位")
    if not EMAIL_RE.fullmatch(email) or len(email) > 254:
        return jsonify(ok=False, err="请填写正确的邮箱地址")
    db = get_db()
    if db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
        return jsonify(ok=False, err="用户名已被注册")
    if db.execute("SELECT 1 FROM users WHERE lower(email)=lower(?)", (email,)).fetchone():
        return jsonify(ok=False, err="该邮箱已被注册")
    invite = None
    if REQUIRE_INVITE:
        invite = db.execute("""SELECT * FROM invitations
            WHERE code_hash=? AND active=1 AND expires_at>? AND used_count<max_uses""",
            (invite_hash(invitation), time.time())).fetchone()
        if not invite:
            return jsonify(ok=False, err="邀请码无效、已过期或已用完"), 403
    ok, err = verify_email_code("register", email, code)
    if not ok:
        return jsonify(ok=False, err=err)
    salt, data_key, wrapped_key = build_user_key_material(p)
    recovery_key, recovery_salt, recovery_wrapped = build_recovery_material(data_key)
    role = "user"  # 公网注册永远是普通用户;管理员只能由服务器初始化或现有管理员授权
    try:
        db.execute("BEGIN IMMEDIATE")
        if REQUIRE_INVITE:
            invite = db.execute("""SELECT * FROM invitations
                WHERE id=? AND active=1 AND expires_at>? AND used_count<max_uses""",
                (invite["id"], time.time())).fetchone()
            if not invite:
                db.rollback()
                return jsonify(ok=False, err="邀请码刚刚已被用完，请联系管理员"), 409
        cur = db.execute("""INSERT INTO users(
            username,pw_hash,salt,role,phone,email,email_verified,wrapped_key,
            recovery_salt,recovery_wrapped_key,created
        ) VALUES(?,?,?,?,?, ?,1,?,?,?,?)""",
            (u, generate_password_hash(p), salt, role, "", email, wrapped_key,
             recovery_salt, recovery_wrapped, now_str()))
        if REQUIRE_INVITE:
            db.execute("""UPDATE invitations SET used_count=used_count+1,
                active=CASE WHEN used_count+1>=max_uses THEN 0 ELSE active END WHERE id=?""",
                (invite["id"],))
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify(ok=False, err="用户名或邮箱已被注册"), 409
    add_log(None, "注册", u, f"邮箱{mask_email(email)},角色:{'管理员' if role=='admin' else '普通用户'}")
    start_session(cur.lastrowid, data_key)
    return jsonify(ok=True, role=role, recovery_key=recovery_key,
                   msg="注册成功，请立即保存保险箱恢复密钥")

@app.route("/api/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    ident = clean_text(d.get("username"), 254)  # 支持用户名、邮箱或旧版手机号
    p = d.get("password") or ""
    limit_key = client_ip() + ":" + sha256(ident.lower().encode("utf-8")).hexdigest()[:12]
    if rate_limited("login", limit_key, 10, 300):
        return jsonify(ok=False, err="登录尝试过于频繁，请 5 分钟后再试"), 429
    db = get_db()
    row = db.execute("""SELECT * FROM users WHERE username=?
        OR (lower(email)=lower(?) AND email<>'') OR (phone=? AND phone<>'')""",
        (ident, ident, ident)).fetchone()
    if not row or not check_password_hash(row["pw_hash"], p):
        safe_ident = mask_email(ident) if "@" in ident else ("手机号尾号" + ident[-4:] if PHONE_RE.match(ident) else ident)
        add_log(None, "登录失败", safe_ident, "凭据校验失败")
        return jsonify(ok=False, err="用户名/邮箱或密码错误")
    if not row["active"]:
        return jsonify(ok=False, err="账号已被停用,请联系管理员")
    try:
        data_key = get_user_data_key(row, p, db)
    except RuntimeError:
        add_log(row["id"], "登录失败", row["username"], "用户数据密钥解包失败")
        return jsonify(ok=False, err="保险箱密钥损坏,请联系管理员"), 500
    start_session(row["id"], data_key)
    add_log(row["id"], "登录", row["username"], "登录成功")
    return jsonify(ok=True, username=row["username"], role=row["role"], msg="登录成功")

@app.route("/api/logout", methods=["POST"])
def logout():
    uid = session.get("uid")
    if uid: add_log(uid, "登出", session.get("username",""))
    end_session()
    return jsonify(ok=True)

@app.route("/api/me")
@login_required
def me():
    db = get_db()
    u = db.execute("""SELECT id,username,role,created,email,email_verified,
        CASE WHEN recovery_wrapped_key<>'' THEN 1 ELSE 0 END AS recovery_ready
        FROM users WHERE id=?""", (session["uid"],)).fetchone()
    user = dict(u)
    user["email_masked"] = mask_email(user.pop("email")) if user["email_verified"] else ""
    return jsonify(ok=True, user=user)

@app.route("/api/email/bind", methods=["POST"])
@login_required
def bind_email():
    d = request.get_json(silent=True) or {}
    email = normalize_email(d.get("email"))
    code = (d.get("email_code") or "").strip()
    current_password = d.get("current_password") or ""
    if not EMAIL_RE.fullmatch(email) or len(email) > 254:
        return jsonify(ok=False, err="邮箱格式不正确"), 400
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    if not check_password_hash(user["pw_hash"], current_password):
        return jsonify(ok=False, err="当前密码错误"), 403
    if db.execute("SELECT 1 FROM users WHERE lower(email)=lower(?) AND id<>?", (email, user["id"])).fetchone():
        return jsonify(ok=False, err="该邮箱已绑定其他账号"), 409
    ok, err = verify_email_code("bind", email, code)
    if not ok:
        return jsonify(ok=False, err=err), 400
    recovery_key = None
    recovery_salt = user["recovery_salt"]
    recovery_wrapped = user["recovery_wrapped_key"]
    if not recovery_salt or not recovery_wrapped:
        recovery_key, recovery_salt, recovery_wrapped = build_recovery_material(user_crypto_key(user))
    db.execute("""UPDATE users SET email=?,email_verified=1,
        recovery_salt=?,recovery_wrapped_key=? WHERE id=?""",
        (email, recovery_salt, recovery_wrapped, user["id"]))
    db.commit()
    add_log(user["id"], "绑定邮箱", mask_email(email), "邮箱验证通过；验证码未记录")
    return jsonify(ok=True, email_masked=mask_email(email), recovery_key=recovery_key,
                   msg="邮箱绑定成功" + ("，请立即保存恢复密钥" if recovery_key else ""))

@app.route("/api/recovery-key", methods=["POST"])
@login_required
def rotate_recovery_key():
    d = request.get_json(silent=True) or {}
    current_password = d.get("current_password") or ""
    email_code = (d.get("email_code") or "").strip()
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    if not user["email_verified"] or not user["email"]:
        return jsonify(ok=False, err="请先绑定并验证邮箱"), 403
    if not check_password_hash(user["pw_hash"], current_password):
        return jsonify(ok=False, err="当前密码错误"), 403
    ok, err = verify_email_code("stepup", user["email"], email_code)
    if not ok:
        return jsonify(ok=False, err=err), 400
    recovery_key, recovery_salt, recovery_wrapped = build_recovery_material(user_crypto_key(user))
    db.execute("UPDATE users SET recovery_salt=?,recovery_wrapped_key=? WHERE id=?",
               (recovery_salt, recovery_wrapped, user["id"]))
    db.commit()
    add_log(user["id"], "轮换恢复密钥", user["username"], "旧恢复密钥已立即失效")
    return jsonify(ok=True, recovery_key=recovery_key, msg="新恢复密钥仅显示一次")

@app.route("/api/password/recover", methods=["POST"])
def recover_password():
    d = request.get_json(silent=True) or {}
    ident = clean_text(d.get("identifier"), 254)
    email_code = (d.get("email_code") or "").strip()
    recovery_key = clean_text(d.get("recovery_key"), 160)
    new_password = d.get("new_password") or ""
    if rate_limited("password-recover", client_ip(), 8, 900):
        return jsonify(ok=False, err="找回请求过于频繁，请稍后再试"), 429
    if len(new_password) < 8 or len(new_password) > 128:
        return jsonify(ok=False, err="新密码需8-128位"), 400
    db = get_db()
    user = db.execute("""SELECT * FROM users WHERE username=?
        OR (lower(email)=lower(?) AND email<>'')""", (ident, ident)).fetchone()
    if not user or not user["active"] or not user["email_verified"]:
        return jsonify(ok=False, err="账号、验证码或恢复密钥无效"), 400
    ok, _ = verify_email_code("reset", user["email"], email_code)
    if not ok:
        return jsonify(ok=False, err="账号、验证码或恢复密钥无效"), 400
    try:
        data_key = unwrap_with_recovery_key(user, recovery_key)
    except RuntimeError:
        add_log(user["id"], "找回密码失败", user["username"], "恢复密钥校验失败")
        return jsonify(ok=False, err="账号、验证码或恢复密钥无效"), 400
    new_salt = os.urandom(16)
    wrapped = aes_encrypt(derive_key(new_password, new_salt), base64.b64encode(data_key).decode())
    db.execute("UPDATE users SET pw_hash=?,salt=?,wrapped_key=? WHERE id=?",
               (generate_password_hash(new_password), new_salt, wrapped, user["id"]))
    db.commit()
    revoke_other_sessions(user["id"])
    add_log(user["id"], "邮箱找回密码", user["username"],
            "邮箱与恢复密钥双重验证通过；用户 DEK 已使用新密码重新包装")
    return jsonify(ok=True, msg="密码已重置，请使用新密码登录")

@app.route("/api/password", methods=["POST"])
@login_required
def change_password():
    d = request.get_json(silent=True) or {}
    current = d.get("current_password") or ""
    new_password = d.get("new_password") or ""
    if len(new_password) < 8 or len(new_password) > 128:
        return jsonify(ok=False, err="新密码需8-128位")
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    if not check_password_hash(user["pw_hash"], current):
        return jsonify(ok=False, err="当前密码错误"), 403
    data_key = user_crypto_key(user)
    new_salt = os.urandom(16)
    wrapped = aes_encrypt(derive_key(new_password, new_salt), base64.b64encode(data_key).decode())
    db.execute("UPDATE users SET pw_hash=?,salt=?,wrapped_key=? WHERE id=?",
               (generate_password_hash(new_password), new_salt, wrapped, user["id"]))
    db.commit()
    revoke_other_sessions(user["id"], session.get("sid"))
    add_log(user["id"], "修改密码", user["username"], "数据密钥已使用新密码重新包装")
    return jsonify(ok=True, msg="密码修改成功")

# ---------------- 密钥 CRUD(个人保险箱) ----------------
@app.route("/api/entries", methods=["GET"])
@login_required
def list_entries():
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    key = user_crypto_key(u)
    rows = db.execute("SELECT * FROM entries WHERE user_id=? ORDER BY updated DESC", (u["id"],)).fetchall()
    out = []
    for r in rows:
        data = json.loads(aes_decrypt(key, r["blob"]))
        out.append({"id": r["id"], "name": r["name"], "cat": r["cat"],
                    "mask": mask_val(data.get("value","")), "has_value": bool(data.get("value")),
                    "expire": data.get("expire",""), "note": data.get("note",""),
                    "created": r["created"], "updated": r["updated"],
                    "history_len": len(data.get("history",[]))})
    return jsonify(ok=True, entries=out)

@app.route("/api/entries", methods=["POST"])
@login_required
def create_entry():
    d = request.get_json(silent=True) or {}
    name = clean_text(d.get("name"), 100)
    value = clean_text(d.get("value"), 4096)
    if not name or not value:
        return jsonify(ok=False, err="名称和密钥内容不能为空")
    cat = clean_text(d.get("cat"), 30) or "其他"
    verr = validate_key_format(cat, value)
    if verr:
        return jsonify(ok=False, err="格式不符: " + verr)
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    key = user_crypto_key(u)
    data = {"value": value, "note": clean_text(d.get("note"), 500),
            "expire": clean_text(d.get("expire"), 20), "history": []}
    blob = aes_encrypt(key, json.dumps(data, ensure_ascii=False))
    now = now_str()
    cur = db.execute("INSERT INTO entries(user_id,name,cat,blob,created,updated) VALUES(?,?,?,?,?,?)",
                     (u["id"], name, cat, blob, now, now))
    db.commit()
    add_log(u["id"], "添加", "密钥:"+name, "新增入库")
    return jsonify(ok=True, id=cur.lastrowid)

@app.route("/api/entries/<int:eid>", methods=["PUT"])
@login_required
def update_entry(eid):
    d = request.get_json(silent=True) or {}
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    r = db.execute("SELECT * FROM entries WHERE id=? AND user_id=?", (eid, u["id"])).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    key = user_crypto_key(u)
    data = json.loads(aes_decrypt(key, r["blob"]))
    if "value" in d and d["value"]:
        nv = clean_text(d["value"], 4096)
        ncat = clean_text(d.get("cat"), 30) or r["cat"]
        verr = validate_key_format(ncat, nv)
        if verr:
            return jsonify(ok=False, err="格式不符: " + verr)
        data["value"] = nv
    if "note" in d: data["note"] = clean_text(d["note"], 500)
    if "expire" in d: data["expire"] = clean_text(d["expire"], 20)
    blob = aes_encrypt(key, json.dumps(data, ensure_ascii=False))
    db.execute("UPDATE entries SET name=?, cat=?, blob=?, updated=? WHERE id=?",
               ((clean_text(d.get("name"), 100) or r["name"]),
                clean_text(d.get("cat"), 30) or r["cat"], blob, now_str(), eid))
    db.commit()
    add_log(u["id"], "编辑", "密钥:"+r["name"], "修改内容/属性")
    return jsonify(ok=True)

@app.route("/api/entries/<int:eid>", methods=["DELETE"])
@login_required
def delete_entry(eid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    r = db.execute("SELECT * FROM entries WHERE id=? AND user_id=?", (eid, u["id"])).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    db.execute("DELETE FROM entries WHERE id=?", (eid,))
    db.commit()
    add_log(u["id"], "删除", "密钥:"+r["name"], "删除密钥")
    return jsonify(ok=True)

@app.route("/api/entries/<int:eid>/reveal", methods=["POST"])
@login_required
def reveal_entry(eid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    r = db.execute("SELECT * FROM entries WHERE id=? AND user_id=?", (eid, u["id"])).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    key = user_crypto_key(u)
    data = json.loads(aes_decrypt(key, r["blob"]))
    add_log(u["id"], "查看", "密钥:"+r["name"], "查看完整内容(已记审计)")
    return jsonify(ok=True, value=data.get("value",""))

@app.route("/api/entries/<int:eid>/rotate", methods=["POST"])
@login_required
def rotate_entry(eid):
    d = request.get_json(silent=True) or {}
    new_value = clean_text(d.get("value"), 4096)
    if not new_value: return jsonify(ok=False, err="新密钥不能为空")
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    r = db.execute("SELECT * FROM entries WHERE id=? AND user_id=?", (eid, u["id"])).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    verr = validate_key_format(r["cat"], new_value)
    if verr:
        return jsonify(ok=False, err="格式不符: " + verr)
    key = user_crypto_key(u)
    data = json.loads(aes_decrypt(key, r["blob"]))
    data.setdefault("history", []).append({"value": data.get("value",""), "time": r["updated"]})
    data["value"] = new_value
    blob = aes_encrypt(key, json.dumps(data, ensure_ascii=False))
    db.execute("UPDATE entries SET blob=?, updated=? WHERE id=?", (blob, now_str(), eid))
    db.commit()
    add_log(u["id"], "轮换", "密钥:"+r["name"], f"已轮换,历史 {len(data['history'])} 条")
    return jsonify(ok=True)

@app.route("/api/entries/<int:eid>/history", methods=["GET"])
@login_required
def entry_history(eid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    r = db.execute("SELECT * FROM entries WHERE id=? AND user_id=?", (eid, u["id"])).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    key = user_crypto_key(u)
    data = json.loads(aes_decrypt(key, r["blob"]))
    return jsonify(ok=True, history=[{"time": h["time"], "mask": mask_val(h["value"])} for h in data.get("history",[])])

# ---------------- 审计日志 ----------------
@app.route("/api/logs", methods=["GET"])
@login_required
def my_logs():
    db = get_db()
    uid = session["uid"]
    u = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
    rows = db.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 300").fetchall() if u["role"]=="admin" \
        else db.execute("SELECT * FROM logs WHERE user_id=? ORDER BY id DESC LIMIT 300", (uid,)).fetchall()
    result = {"ok": True, "logs": [dict(r) for r in rows]}
    if u["role"] == "admin":
        result["integrity"] = verify_audit_chain(db)
    return jsonify(**result)

@app.route("/api/logs/integrity", methods=["GET"])
@admin_required
def audit_integrity():
    return jsonify(**verify_audit_chain(get_db()))

# ---------------- 管理员:用户管理 ----------------
@app.route("/api/users", methods=["GET"])
@admin_required
def list_users():
    db = get_db()
    rows = db.execute("SELECT id,username,role,active,created FROM users ORDER BY id").fetchall()
    return jsonify(ok=True, users=[dict(r) for r in rows])

@app.route("/api/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def toggle_user(uid):
    if uid == session["uid"]:
        return jsonify(ok=False, err="不能停用自己")
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u: return jsonify(ok=False, err="用户不存在"), 404
    db.execute("UPDATE users SET active=? WHERE id=?", (0 if u["active"] else 1, uid))
    db.commit()
    add_log(session["uid"], "用户管理", u["username"], "停用" if u["active"] else "启用")
    return jsonify(ok=True)

@app.route("/api/users/<int:uid>/role", methods=["POST"])
@admin_required
def change_user_role(uid):
    """现有管理员重新验证密码；已绑定邮箱时再做邮箱二次验证。"""
    if uid == session["uid"]:
        return jsonify(ok=False, err="不能修改自己的管理员角色"), 400
    d = request.get_json(silent=True) or {}
    new_role = d.get("role")
    current_password = d.get("current_password") or ""
    email_code = (d.get("email_code") or "").strip()
    if new_role not in ("admin", "user"):
        return jsonify(ok=False, err="角色参数无效"), 400
    db = get_db()
    actor = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    if not check_password_hash(actor["pw_hash"], current_password):
        return jsonify(ok=False, err="当前管理员密码错误"), 403
    if EMAIL_STEP_UP and actor["email_verified"]:
        ok, err = verify_email_code("stepup", actor["email"], email_code)
        if not ok:
            return jsonify(ok=False, err=err), 403
    target = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not target:
        return jsonify(ok=False, err="用户不存在"), 404
    if target["role"] == new_role:
        return jsonify(ok=False, err="用户已经是该角色"), 400
    db.execute("UPDATE users SET role=? WHERE id=?", (new_role, uid))
    db.commit()
    action = "授权管理员" if new_role == "admin" else "撤销管理员"
    detail = "管理员密码复核"
    if EMAIL_STEP_UP and actor["email_verified"]:
        detail += " + 邮箱二次验证"
    add_log(actor["id"], action, target["username"], detail + "后执行")
    return jsonify(ok=True, role=new_role, msg=action + "成功")

# ---------------- 管理员:公网注册邀请码 ----------------
@app.route("/api/invitations", methods=["GET"])
@admin_required
def list_invitations():
    rows = get_db().execute("""SELECT id,expires_at,max_uses,used_count,active,created
        FROM invitations ORDER BY id DESC LIMIT 100""").fetchall()
    now = time.time()
    items = []
    for row in rows:
        item = dict(row)
        item["expired"] = row["expires_at"] <= now
        item["expires"] = datetime.fromtimestamp(row["expires_at"]).strftime("%Y-%m-%d %H:%M")
        items.append(item)
    return jsonify(ok=True, invitations=items)

@app.route("/api/invitations", methods=["POST"])
@admin_required
def create_invitation():
    d = request.get_json(silent=True) or {}
    try:
        hours = max(1, min(int(d.get("hours", 24)), 168))
        max_uses = max(1, min(int(d.get("max_uses", 1)), 100))
    except (TypeError, ValueError):
        return jsonify(ok=False, err="有效期和使用次数必须是整数"), 400
    if rate_limited("invite-create", str(session["uid"]), 20, 3600):
        return jsonify(ok=False, err="生成邀请码过于频繁，请稍后再试"), 429
    code = "KS-" + secrets.token_urlsafe(18).upper()
    expires_at = time.time() + hours * 3600
    db = get_db()
    cur = db.execute("""INSERT INTO invitations
        (code_hash,created_by,expires_at,max_uses,used_count,active,created)
        VALUES(?,?,?,?,0,1,?)""",
        (invite_hash(code), session["uid"], expires_at, max_uses, now_str()))
    db.commit()
    add_log(session["uid"], "生成邀请码", f"邀请码#{cur.lastrowid}",
            f"有效{hours}小时,最多{max_uses}人使用；明文仅本次展示")
    return jsonify(ok=True, id=cur.lastrowid, invitation=code,
                   expires=datetime.fromtimestamp(expires_at).strftime("%Y-%m-%d %H:%M"),
                   max_uses=max_uses,
                   msg="邀请码仅显示一次，请通过可信渠道发送")

@app.route("/api/invitations/<int:iid>", methods=["DELETE"])
@admin_required
def revoke_invitation(iid):
    db = get_db()
    row = db.execute("SELECT id,active FROM invitations WHERE id=?", (iid,)).fetchone()
    if not row:
        return jsonify(ok=False, err="邀请码不存在"), 404
    db.execute("UPDATE invitations SET active=0 WHERE id=?", (iid,))
    db.commit()
    add_log(session["uid"], "撤销邀请码", f"邀请码#{iid}", "邀请码已立即失效")
    return jsonify(ok=True)

# ---------------- 固定上游厂商白名单 ----------------
# URL 不能由浏览器提交，避免代理接口被利用访问内网（SSRF）。
PROVIDERS = {
    "DeepSeek": {
        "url": "https://api.deepseek.com/chat/completions",
        "model": "deepseek-v4-flash",
    },
    "OpenAI": {
        "url": "https://api.openai.com/v1/chat/completions",
        "model": "gpt-5-mini",
        "max_tokens_param": "max_completion_tokens",
    },
    "通义千问": {
        "url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "model": "qwen-plus",
    },
    "Kimi": {
        "url": "https://api.moonshot.cn/v1/chat/completions",
        "model": "kimi-k2.5",
    },
    "智谱清言": {
        "url": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "model": "glm-5.2",
    },
    "硅基流动": {
        "url": "https://api.siliconflow.cn/v1/chat/completions",
        "model": "Pro/zai-org/GLM-4.7",
    },
}

def call_provider(provider, api_key, model, prompt):
    cfg = PROVIDERS[provider]
    endpoint = urlsplit(cfg["url"])
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password:
        raise ValueError("provider_endpoint_not_https")
    body = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
    }
    body[cfg.get("max_tokens_param", "max_tokens")] = MAX_OUTPUT_TOKENS
    payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
    upstream = urllib.request.Request(cfg["url"], data=payload, method="POST", headers={
        "Authorization": "Bearer " + api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "KeyShield/2.11",
    })
    # URL 只来自上方代码内置的 PROVIDERS 白名单，并在调用前强制校验 HTTPS。
    with urllib.request.urlopen(upstream, timeout=30) as resp:  # nosec B310
        raw = resp.read(2 * 1024 * 1024 + 1)
        if len(raw) > 2 * 1024 * 1024:
            raise ValueError("upstream_response_too_large")
    data = json.loads(raw.decode("utf-8"))
    choices = data.get("choices") or []
    answer = choices[0].get("message", {}).get("content") if choices else None
    if not isinstance(answer, str):
        raise ValueError("upstream_response_invalid")
    usage = data.get("usage") or {}
    return answer, {
        "input_tokens": int(usage.get("prompt_tokens") or 0),
        "output_tokens": int(usage.get("completion_tokens") or 0),
        "total_tokens": int(usage.get("total_tokens") or 0),
    }

# ---------------- 团队:真实团队与两种协作模式 ----------------
def today_str():
    """日期粒度,成员到期日当天仍视为有效至当日结束"""
    return datetime.now().strftime("%Y-%m-%d")

def get_team(db, tid):
    return db.execute("SELECT * FROM teams WHERE id=?", (tid,)).fetchone()

def team_membership(db, uid, tid):
    return db.execute("SELECT * FROM team_members WHERE team_id=? AND user_id=?",
                      (tid, uid)).fetchone()

def active_membership(db, uid, tid):
    """有效成员:leader 恒有效;member 需 status='active' 且未过期"""
    m = team_membership(db, uid, tid)
    if not m: return None
    if m["role"] == "leader": return m
    if m["status"] != "active": return None
    if m["expires_at"] and m["expires_at"] < today_str(): return None
    return m

def require_team_member(db, uid, tid, need_leader=False):
    """返回 (成员行, None) 或 (None, err)。用于路由内统一 403。"""
    m = active_membership(db, uid, tid)
    if not m:
        return None, "你不是该团队的生效成员或成员已过期"
    if need_leader and m["role"] != "leader":
        return None, "该操作仅主管理者可执行"
    return m, None

def team_key_ids(db, tid):
    rows = db.execute("SELECT id FROM shared_keys WHERE team_id=?", (tid,)).fetchall()
    return [r["id"] for r in rows]

def revoke_team_grants(db, uid, tid):
    """成员被移除/过期时回收其在本团全部领用,防止残留 grant"""
    db.execute("DELETE FROM grants WHERE user_id=? AND key_id IN (SELECT id FROM shared_keys WHERE team_id=?)",
               (uid, tid))

def gen_join_code():
    """入队码:KS- 前缀 + 6 位混淆字母数字(去掉易混淆的 0/O/1/I/L)"""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "KS-" + "".join(secrets.choice(alphabet) for _ in range(6))

# ---------------- 管理员:托管密钥(发卡中心) ----------------
@app.route("/api/shared", methods=["GET"])
@login_required
def list_shared():
    db = get_db()
    rows = db.execute("SELECT * FROM shared_keys WHERE team_id IS NULL ORDER BY id DESC").fetchall()
    skey = get_site_key()
    uid = session["uid"]
    out = []
    granted_ids = {r["key_id"] for r in db.execute(
        "SELECT key_id FROM grants WHERE user_id=? AND status='active'", (uid,)).fetchall()}
    for r in rows:
        try:
            data = json.loads(aes_decrypt(skey, r["blob"]))
            m = mask_val(data.get("value",""))
        except Exception:
            m = "****"
        out.append({"id": r["id"], "name": r["name"], "cat": r["cat"], "note": r["note"],
                    "mask": m, "mode": r["mode"], "granted": r["id"] in granted_ids,
                    "model": r["model"] or PROVIDERS.get(r["cat"], {}).get("model", ""),
                    "provider_supported": r["cat"] in PROVIDERS,
                    "created": r["created"]})
    return jsonify(ok=True, shared=out)

@app.route("/api/shared", methods=["POST"])
@admin_required
def create_shared():
    d = request.get_json(silent=True) or {}
    name = clean_text(d.get("name"), 100)
    value = clean_text(d.get("value"), 4096)
    if not name or not value:
        return jsonify(ok=False, err="名称和密钥内容不能为空")
    cat = d.get("cat") or "其他"
    verr = validate_key_format(cat, value)
    if verr:
        return jsonify(ok=False, err="格式不符: " + verr)
    mode = d.get("mode") or "proxy"
    if mode not in ("proxy", "direct"):
        mode = "proxy"
    if mode == "direct" and not ALLOW_DIRECT_SHARED:
        return jsonify(ok=False, err="公网环境禁止直接下发真实密钥，请使用仅代调用模式"), 403
    model = clean_text(d.get("model"), 120) or PROVIDERS.get(cat, {}).get("model", "")
    if mode == "proxy" and cat not in PROVIDERS and not DEMO_MODE:
        return jsonify(ok=False, err="该分类尚未配置安全的厂商代理地址"), 400
    if mode == "proxy" and not model:
        return jsonify(ok=False, err="请填写调用模型名称"), 400
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    blob = aes_encrypt(get_site_key(), json.dumps({"value": value}, ensure_ascii=False))
    now = now_str()
    note = clean_text(d.get("note"), 500)
    cur = db.execute("INSERT INTO shared_keys(name,cat,blob,note,mode,model,created,updated) VALUES(?,?,?,?,?,?,?,?)",
                     (name, cat, blob, note, mode, model, now, now))
    db.commit()
    add_log(u["id"], "托管密钥", name, ("直接下发模式, 领用者可查看全文" if mode=="direct" else "仅代调用模式, key 不下发"))
    return jsonify(ok=True, id=cur.lastrowid)

@app.route("/api/shared/<int:kid>/reveal", methods=["POST"])
@login_required
def reveal_shared(kid):
    """领用者查看托管密钥全文(仅 direct 模式;proxy 模式一律拒绝)"""
    if not ALLOW_DIRECT_SHARED:
        return jsonify(ok=False, err="公网环境已禁止直接下发真实密钥"), 403
    db = get_db()
    uid = session["uid"]
    r = db.execute("SELECT * FROM shared_keys WHERE id=? AND team_id IS NULL", (kid,)).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    if r["mode"] != "direct":
        return jsonify(ok=False, err="该密钥为「仅代调用」模式,不支持下发查看"), 403
    grant = db.execute("SELECT 1 FROM grants WHERE user_id=? AND key_id=? AND status='active'", (uid, kid)).fetchone()
    if not grant:
        return jsonify(ok=False, err="请先向管理员领用该密钥"), 403
    data = json.loads(aes_decrypt(get_site_key(), r["blob"]))
    add_log(uid, "查看下发密钥", "托管密钥:"+r["name"], "直接下发模式, 查看全文(审计留痕)")
    return jsonify(ok=True, value=data.get("value",""), msg="密钥已下发展示")

@app.route("/api/shared/<int:kid>/grant", methods=["POST"])
@login_required
def grant_key(kid):
    """用户申请领用 / 管理员授权 —— 演示版:直接授予"""
    db = get_db()
    uid = session["uid"]
    r = db.execute("SELECT * FROM shared_keys WHERE id=? AND team_id IS NULL", (kid,)).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    ex = db.execute("SELECT * FROM grants WHERE user_id=? AND key_id=?", (uid, kid)).fetchone()
    if ex and ex["status"] == "active":
        return jsonify(ok=False, err="你已领用该密钥")
    try:
        if ex:
            db.execute("UPDATE grants SET granted_by=?,granted_at=?,status='active' WHERE id=?",
                       (session["uid"], now_str(), ex["id"]))
        else:
            db.execute("INSERT INTO grants(user_id,key_id,granted_by,granted_at,status) VALUES(?,?,?,?,?)",
                       (uid, kid, session["uid"], now_str(), "active"))
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify(ok=False, err="你已领用该密钥"), 409
    add_log(uid, "领用", "托管密钥:"+r["name"], "申请并领用(已授权调用,密钥不出服务器)")
    return jsonify(ok=True)

def _proxy_call(uid, r, label, action_success="调用", action_fail="调用失败",
                prompt_override=None, virtual_key_id=None, virtual_daily_limit=None):
    """代调用公共实现:r 为 shared_keys 行;label 用于审计日志。真实 key 绝不进入响应或日志。"""
    db = get_db()
    kid = r["id"]
    if r["mode"] != "proxy":
        return jsonify(ok=False, err="直接下发密钥不支持平台代理调用"), 400
    if rate_limited("proxy-user", str(uid), 30, 60):
        return jsonify(ok=False, err="调用过于频繁，请稍后再试"), 429
    today_start = datetime.now().strftime("%Y-%m-%d 00:00:00")
    if virtual_key_id:
        calls_today = db.execute("""SELECT COUNT(*) FROM usage_records
            WHERE virtual_key_id=? AND started>=?""", (virtual_key_id, today_start)).fetchone()[0]
        effective_limit = min(DAILY_CALL_LIMIT, int(virtual_daily_limit or DAILY_CALL_LIMIT))
    else:
        calls_today = db.execute("SELECT COUNT(*) FROM usage_records WHERE user_id=? AND started>=?",
                                 (uid, today_start)).fetchone()[0]
        effective_limit = DAILY_CALL_LIMIT
    if calls_today >= effective_limit:
        return jsonify(ok=False, err=f"今日安全调用额度已用完（{effective_limit} 次），请联系管理员"), 429
    d = request.get_json(silent=True) or {}
    prompt = clean_text(prompt_override if prompt_override is not None else d.get("prompt"), 8000)
    provider = r["cat"]
    model = r["model"] or PROVIDERS.get(provider, {}).get("model", "")
    request_id = "KSR-" + uuid.uuid4().hex
    started_at = time.perf_counter()
    db.execute("""INSERT INTO usage_records
        (request_id,user_id,key_id,provider,model,started,status,source_ip_hash,virtual_key_id)
        VALUES(?,?,?,?,?,?,?,?,?)""",
        (request_id, uid, kid, provider, model, now_str(), "pending", ip_fingerprint(), virtual_key_id))
    db.commit()

    if not prompt:
        if not DEMO_MODE:
            db.execute("UPDATE usage_records SET finished=?,status=?,error_code=? WHERE request_id=?",
                       (now_str(), "failed", "prompt_required", request_id))
            db.commit()
            return jsonify(ok=False, err="请输入要发送给模型的问题", request_id=request_id), 400
        latency = max(1, int((time.perf_counter() - started_at) * 1000))
        db.execute("UPDATE usage_records SET finished=?,status=?,latency_ms=? WHERE request_id=?",
                   (now_str(), "demo", latency, request_id))
        db.commit()
        add_log(uid, action_success, label, f"演示代调成功,请求号:{request_id}")
        return jsonify(ok=True, msg="演示调用成功(key未下发客户端)", request_id=request_id,
                       model=model, demo=True, usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0})

    if provider not in PROVIDERS:
        db.execute("UPDATE usage_records SET finished=?,status=?,error_code=? WHERE request_id=?",
                   (now_str(), "failed", "provider_not_supported", request_id))
        db.commit()
        return jsonify(ok=False, err="该厂商尚未配置服务端代理", request_id=request_id), 400
    try:
        secret_data = json.loads(aes_decrypt(get_site_key(), r["blob"]))
        answer, usage = call_provider(provider, secret_data.get("value", ""), model, prompt)
    except urllib.error.HTTPError as exc:
        latency = int((time.perf_counter() - started_at) * 1000)
        error_code = "upstream_http_" + str(exc.code)
        db.execute("UPDATE usage_records SET finished=?,status=?,latency_ms=?,error_code=? WHERE request_id=?",
                   (now_str(), "failed", latency, error_code, request_id))
        db.commit()
        add_log(uid, action_fail, label, f"上游HTTP错误,请求号:{request_id}")
        return jsonify(ok=False, err="厂商接口拒绝了请求，请管理员检查密钥、模型或额度",
                       request_id=request_id), 502
    except (urllib.error.URLError, TimeoutError):
        latency = int((time.perf_counter() - started_at) * 1000)
        db.execute("UPDATE usage_records SET finished=?,status=?,latency_ms=?,error_code=? WHERE request_id=?",
                   (now_str(), "failed", latency, "upstream_unavailable", request_id))
        db.commit()
        add_log(uid, action_fail, label, f"上游不可用,请求号:{request_id}")
        return jsonify(ok=False, err="暂时无法连接厂商接口，请稍后再试", request_id=request_id), 502
    except (ValueError, KeyError, json.JSONDecodeError):
        latency = int((time.perf_counter() - started_at) * 1000)
        db.execute("UPDATE usage_records SET finished=?,status=?,latency_ms=?,error_code=? WHERE request_id=?",
                   (now_str(), "failed", latency, "upstream_invalid_response", request_id))
        db.commit()
        add_log(uid, action_fail, label, f"上游响应异常,请求号:{request_id}")
        return jsonify(ok=False, err="厂商返回了无法识别的响应", request_id=request_id), 502

    latency = int((time.perf_counter() - started_at) * 1000)
    db.execute("""UPDATE usage_records SET finished=?,input_tokens=?,output_tokens=?,total_tokens=?,
        status='success',latency_ms=? WHERE request_id=?""",
        (now_str(), usage["input_tokens"], usage["output_tokens"], usage["total_tokens"], latency, request_id))
    db.commit()
    add_log(uid, action_success, label,
            f"系统代调成功,模型:{model},Token:{usage['total_tokens']},请求号:{request_id}")
    return jsonify(ok=True, answer=answer, usage=usage, request_id=request_id,
                   provider=provider, model=model, latency_ms=latency)

@app.route("/api/shared/<int:kid>/use", methods=["POST"])
@login_required
def use_shared(kid):
    """服务端代调用固定白名单厂商；真实 key 绝不进入响应或日志。"""
    db = get_db()
    uid = session["uid"]
    r = db.execute("SELECT * FROM shared_keys WHERE id=? AND team_id IS NULL", (kid,)).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    grant = db.execute("SELECT 1 FROM grants WHERE user_id=? AND key_id=? AND status='active'", (uid, kid)).fetchone()
    if not grant:
        return jsonify(ok=False, err="请先向管理员领用该密钥"), 403
    return _proxy_call(uid, r, "托管密钥:"+r["name"])

@app.route("/api/usage", methods=["GET"])
@login_required
def list_usage():
    db = get_db()
    uid = session["uid"]
    actor = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
    base = """SELECT ur.*,u.username,sk.name AS key_name FROM usage_records ur
        LEFT JOIN users u ON u.id=ur.user_id LEFT JOIN shared_keys sk ON sk.id=ur.key_id"""
    if actor["role"] == "admin":
        rows = db.execute(base + " ORDER BY ur.id DESC LIMIT 300").fetchall()
        totals = db.execute("""SELECT COUNT(*) calls,COALESCE(SUM(total_tokens),0) tokens,
            COALESCE(SUM(CASE WHEN status='success' OR status='demo' THEN 1 ELSE 0 END),0) successful
            FROM usage_records""").fetchone()
    else:
        rows = db.execute(base + " WHERE ur.user_id=? ORDER BY ur.id DESC LIMIT 300", (uid,)).fetchall()
        totals = db.execute("""SELECT COUNT(*) calls,COALESCE(SUM(total_tokens),0) tokens,
            COALESCE(SUM(CASE WHEN status='success' OR status='demo' THEN 1 ELSE 0 END),0) successful
            FROM usage_records WHERE user_id=?""", (uid,)).fetchone()
    return jsonify(ok=True, usage=[dict(row) for row in rows], summary=dict(totals))

@app.route("/api/shared/<int:kid>", methods=["DELETE"])
@admin_required
def delete_shared(kid):
    db = get_db()
    r = db.execute("SELECT * FROM shared_keys WHERE id=? AND team_id IS NULL", (kid,)).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    db.execute("UPDATE virtual_keys SET active=0,revoked_at=? WHERE key_id=? AND active=1", (now_str(), kid))
    db.execute("DELETE FROM shared_keys WHERE id=?", (kid,))
    db.execute("DELETE FROM grants WHERE key_id=?", (kid,))
    db.commit()
    add_log(session["uid"], "撤销托管", r["name"], "撤销托管密钥,全部领用立即失效")
    return jsonify(ok=True)

# ---------------- 团队:创建与管理 ----------------
@app.route("/api/teams", methods=["POST"])
@login_required
def create_team():
    """任何登录用户可建团,建团者成为主管理者;生成唯一入队码"""
    d = request.get_json(silent=True) or {}
    name = clean_text(d.get("name"), 60)
    mode = d.get("mode") or "class"
    if mode not in ("class", "research"):
        mode = "class"
    if not name:
        return jsonify(ok=False, err="团队名称不能为空")
    db = get_db()
    uid = session["uid"]
    if rate_limited("team-create", str(uid), 10, 3600):
        return jsonify(ok=False, err="创建团队过于频繁，请稍后再试"), 429
    now = now_str()
    code = gen_join_code()
    tid = None
    for _ in range(5):
        try:
            db.execute("BEGIN IMMEDIATE")
            cur = db.execute("INSERT INTO teams(name,mode,leader_id,join_code,created) VALUES(?,?,?,?,?)",
                             (name, mode, uid, code, now))
            tid = cur.lastrowid
            db.execute("INSERT INTO team_members(team_id,user_id,role,status,joined_at) VALUES(?,?,?,?,?)",
                       (tid, uid, "leader", "active", now))
            db.commit()
            break
        except sqlite3.IntegrityError:
            db.rollback()
            code = gen_join_code()
    if tid is None:
        return jsonify(ok=False, err="入队码生成失败,请重试"), 500
    add_log(uid, "创建团队", f"团队#{tid}:{name}", f"{'班级管控' if mode=='class' else '科研协作'}模式")
    return jsonify(ok=True, id=tid, join_code=code)

@app.route("/api/teams", methods=["GET"])
@login_required
def list_my_teams():
    """我的团队(含已过期成员身份,前端据此打标;操作仍会被拦截)"""
    db = get_db()
    uid = session["uid"]
    today = today_str()
    rows = db.execute("""SELECT t.*, tm.role,
        (SELECT COUNT(*) FROM team_members WHERE team_id=t.id AND status='active') AS member_count
        FROM teams t JOIN team_members tm ON tm.team_id=t.id
        WHERE tm.user_id=? AND tm.status='active' ORDER BY t.id DESC""", (uid,)).fetchall()
    out = [{"id": r["id"], "name": r["name"], "mode": r["mode"], "role": r["role"],
            "member_count": r["member_count"], "created": r["created"],
            "expired": bool(r["expires_at"] and r["expires_at"] < today)} for r in rows]
    return jsonify(ok=True, teams=out)

@app.route("/api/teams/<int:tid>", methods=["GET"])
@login_required
def team_detail(tid):
    """团队详情+成员列表;仅主管理者可见入队码"""
    db = get_db()
    uid = session["uid"]
    m, err = require_team_member(db, uid, tid)
    if not m: return jsonify(ok=False, err=err), 403
    t = get_team(db, tid)
    if not t: return jsonify(ok=False, err="团队不存在"), 404
    members = db.execute("""SELECT tm.id, tm.user_id, tm.role, tm.status, tm.joined_at, tm.expires_at, u.username
        FROM team_members tm JOIN users u ON u.id=tm.user_id
        WHERE tm.team_id=? ORDER BY CASE tm.role WHEN 'leader' THEN 0 ELSE 1 END, tm.id""", (tid,)).fetchall()
    out = {"id": t["id"], "name": t["name"], "mode": t["mode"], "leader_id": t["leader_id"],
           "created": t["created"], "is_leader": m["role"] == "leader",
           "members": [dict(r) for r in members]}
    if m["role"] == "leader":
        out["join_code"] = t["join_code"]
    return jsonify(ok=True, team=out)

@app.route("/api/teams/<int:tid>/join", methods=["POST"])
@login_required
def join_team(tid):
    """凭入队码申请加入(pending);rejected 可重新申请"""
    d = request.get_json(silent=True) or {}
    code = clean_text(d.get("join_code"), 20).upper()
    db = get_db()
    uid = session["uid"]
    if rate_limited("team-join", str(uid), 12, 600):
        return jsonify(ok=False, err="入队尝试过于频繁，请稍后再试"), 429
    t = get_team(db, tid)
    if not t: return jsonify(ok=False, err="团队不存在"), 404
    if not code or t["join_code"] != code:
        return jsonify(ok=False, err="入队码不正确"), 403
    ex = team_membership(db, uid, tid)
    now = now_str()
    if ex:
        if ex["status"] == "active":
            return jsonify(ok=False, err="你已在该团队中")
        if ex["status"] == "pending":
            return jsonify(ok=False, err="已提交申请,等待主管理者审核")
        db.execute("UPDATE team_members SET status='pending', joined_at=? WHERE id=?", (now, ex["id"]))
    else:
        db.execute("INSERT INTO team_members(team_id,user_id,role,status,joined_at) VALUES(?,?,?,?,?)",
                   (tid, uid, "member", "pending", now))
    db.commit()
    add_log(uid, "申请加入", f"团队#{tid}:{t['name']}", "凭入队码申请加入")
    return jsonify(ok=True)

@app.route("/api/teams/join-by-code", methods=["POST"])
@login_required
def join_team_by_code():
    """前端只有入队码、不知道团队 id,按码直接申请加入"""
    d = request.get_json(silent=True) or {}
    code = clean_text(d.get("join_code"), 20).upper()
    db = get_db()
    uid = session["uid"]
    if rate_limited("team-join", str(uid), 12, 600):
        return jsonify(ok=False, err="入队尝试过于频繁，请稍后再试"), 429
    if not code:
        return jsonify(ok=False, err="请输入入队码"), 400
    t = db.execute("SELECT * FROM teams WHERE join_code=?", (code,)).fetchone()
    if not t:
        return jsonify(ok=False, err="入队码不存在"), 404
    ex = team_membership(db, uid, t["id"])
    now = now_str()
    if ex:
        if ex["status"] == "active":
            return jsonify(ok=False, err="你已在该团队中")
        if ex["status"] == "pending":
            return jsonify(ok=False, err="已提交申请,等待主管理者审核")
        db.execute("UPDATE team_members SET status='pending', joined_at=? WHERE id=?", (now, ex["id"]))
    else:
        db.execute("INSERT INTO team_members(team_id,user_id,role,status,joined_at) VALUES(?,?,?,?,?)",
                   (t["id"], uid, "member", "pending", now))
    db.commit()
    add_log(uid, "申请加入", f"团队#{t['id']}:{t['name']}", "凭入队码申请加入")
    return jsonify(ok=True, team_id=t["id"], team_name=t["name"])

@app.route("/api/teams/<int:tid>/members", methods=["POST"])
@login_required
def add_team_member(tid):
    """主管理者按用户名直加成员(班级模式发卡),可带有效期"""
    d = request.get_json(silent=True) or {}
    username = clean_text(d.get("username"), 64)
    expires_at = clean_text(d.get("expires_at"), 10)
    db = get_db()
    uid = session["uid"]
    m, err = require_team_member(db, uid, tid, need_leader=True)
    if not m: return jsonify(ok=False, err=err), 403
    t = get_team(db, tid)
    if not username:
        return jsonify(ok=False, err="请输入成员用户名")
    if expires_at and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires_at):
        return jsonify(ok=False, err="有效期格式应为 YYYY-MM-DD")
    target = db.execute("SELECT * FROM users WHERE username=? AND active=1", (username,)).fetchone()
    if not target:
        return jsonify(ok=False, err="未找到该用户名或账号已停用"), 404
    if target["id"] == uid:
        return jsonify(ok=False, err="不能把自己加为成员(你已是主管理者)")
    ex = team_membership(db, target["id"], tid)
    now = now_str()
    if ex:
        if ex["role"] == "leader":
            return jsonify(ok=False, err="该用户已是团队主管理者")
        db.execute("UPDATE team_members SET status='active', joined_at=?, expires_at=? WHERE id=?",
                   (now, expires_at or None, ex["id"]))
    else:
        db.execute("INSERT INTO team_members(team_id,user_id,role,status,joined_at,expires_at) VALUES(?,?,?,?,?,?)",
                   (tid, target["id"], "member", "active", now, expires_at or None))
    db.commit()
    add_log(uid, "直加成员", f"团队#{tid}:{t['name']}", f"{username} (有效期:{expires_at or '长期'})")
    return jsonify(ok=True)

def _leader_guard(db, uid, tid):
    """团队管理操作的通用鉴权:返回 (团队, err)"""
    m, err = require_team_member(db, uid, tid, need_leader=True)
    if not m:
        return None, err
    t = get_team(db, tid)
    if not t:
        return None, "团队不存在"
    return t, None

@app.route("/api/teams/<int:tid>/members/<int:target_uid>/approve", methods=["POST"])
@login_required
def approve_member(tid, target_uid):
    db = get_db()
    uid = session["uid"]
    t, err = _leader_guard(db, uid, tid)
    if not t: return jsonify(ok=False, err=err), 403
    mem = team_membership(db, target_uid, tid)
    if not mem or mem["role"] == "leader":
        return jsonify(ok=False, err="成员不存在"), 404
    if mem["status"] == "active":
        return jsonify(ok=True)
    if mem["status"] != "pending":
        return jsonify(ok=False, err="该成员无需审核")
    db.execute("UPDATE team_members SET status='active', joined_at=? WHERE id=?", (now_str(), mem["id"]))
    db.commit()
    add_log(uid, "审核成员", f"团队#{tid}:{t['name']}", f"通过 {mem['user_id']}")
    return jsonify(ok=True)

@app.route("/api/teams/<int:tid>/members/<int:target_uid>/reject", methods=["POST"])
@login_required
def reject_member(tid, target_uid):
    db = get_db()
    uid = session["uid"]
    t, err = _leader_guard(db, uid, tid)
    if not t: return jsonify(ok=False, err=err), 403
    mem = team_membership(db, target_uid, tid)
    if not mem or mem["role"] == "leader":
        return jsonify(ok=False, err="成员不存在"), 404
    if mem["status"] != "pending":
        return jsonify(ok=False, err="该成员无需审核")
    db.execute("UPDATE team_members SET status='rejected' WHERE id=?", (mem["id"],))
    db.commit()
    add_log(uid, "拒绝成员", f"团队#{tid}:{t['name']}", f"拒绝 {mem['user_id']}")
    return jsonify(ok=True)

@app.route("/api/teams/<int:tid>/members/<int:target_uid>/remove", methods=["POST"])
@login_required
def remove_member(tid, target_uid):
    db = get_db()
    uid = session["uid"]
    t, err = _leader_guard(db, uid, tid)
    if not t: return jsonify(ok=False, err=err), 403
    if target_uid == uid:
        return jsonify(ok=False, err="不能移除自己"), 403
    mem = team_membership(db, target_uid, tid)
    if not mem or mem["role"] == "leader":
        return jsonify(ok=False, err="成员不存在"), 404
    db.execute("DELETE FROM team_members WHERE id=?", (mem["id"],))
    revoke_team_grants(db, target_uid, tid)
    db.commit()
    add_log(uid, "移除成员", f"团队#{tid}:{t['name']}", f"移除 {mem['user_id']},领用已回收")
    return jsonify(ok=True)

@app.route("/api/teams/<int:tid>/members/<int:target_uid>/expiry", methods=["POST"])
@login_required
def set_member_expiry(tid, target_uid):
    """设置成员有效期;空串=长期;设为过去日期则立即回收领用"""
    d = request.get_json(silent=True) or {}
    expires_at = clean_text(d.get("expires_at"), 10)
    db = get_db()
    uid = session["uid"]
    t, err = _leader_guard(db, uid, tid)
    if not t: return jsonify(ok=False, err=err), 403
    if expires_at and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", expires_at):
        return jsonify(ok=False, err="有效期格式应为 YYYY-MM-DD")
    mem = team_membership(db, target_uid, tid)
    if not mem or mem["role"] == "leader":
        return jsonify(ok=False, err="成员不存在"), 404
    db.execute("UPDATE team_members SET expires_at=? WHERE id=?", (expires_at or None, mem["id"]))
    if expires_at and expires_at < today_str():
        revoke_team_grants(db, target_uid, tid)
    db.commit()
    add_log(uid, "设置成员到期", f"团队#{tid}:{t['name']}", f"成员 {mem['user_id']} 有效期 {expires_at or '长期'}")
    return jsonify(ok=True)

@app.route("/api/teams/<int:tid>", methods=["DELETE"])
@login_required
def delete_team(tid):
    """解散团队:清成员关系、团队密钥及领用"""
    db = get_db()
    uid = session["uid"]
    t, err = _leader_guard(db, uid, tid)
    if not t: return jsonify(ok=False, err=err), 403
    db.execute("DELETE FROM team_members WHERE team_id=?", (tid,))
    db.execute("""UPDATE virtual_keys SET active=0,revoked_at=?
        WHERE key_id IN (SELECT id FROM shared_keys WHERE team_id=?) AND active=1""", (now_str(), tid))
    db.execute("DELETE FROM grants WHERE key_id IN (SELECT id FROM shared_keys WHERE team_id=?)", (tid,))
    db.execute("DELETE FROM shared_keys WHERE team_id=?", (tid,))
    db.execute("DELETE FROM teams WHERE id=?", (tid,))
    db.commit()
    add_log(uid, "解散团队", f"团队#{tid}:{t['name']}", "解散团队,密钥与成员关系已清理")
    return jsonify(ok=True)

# ---------------- 团队:团队密钥(两种协作模式) ----------------
def _team_key_permission(db, uid, tid, key_action):
    """团队密钥操作通用鉴权:返回 (团队, 成员, err)。
    key_action: 增改删。班级模式仅 leader 可执行;科研模式任何 active 成员可执行。"""
    t = get_team(db, tid)
    if not t: return None, None, "团队不存在"
    m, err = require_team_member(db, uid, tid)
    if not m: return None, None, err
    if key_action and t["mode"] == "class" and m["role"] != "leader":
        return None, None, "班级模式仅主管理者可" + ("添加" if key_action=="add" else "修改/删除") + "密钥"
    return t, m, None

@app.route("/api/teams/<int:tid>/keys", methods=["GET"])
@login_required
def list_team_keys(tid):
    db = get_db()
    uid = session["uid"]
    t, m, err = _team_key_permission(db, uid, tid, None)
    if not t: return jsonify(ok=False, err=err), 403
    rows = db.execute("SELECT * FROM shared_keys WHERE team_id=? ORDER BY id DESC", (tid,)).fetchall()
    skey = get_site_key()
    granted_ids = {r["key_id"] for r in db.execute(
        "SELECT key_id FROM grants WHERE user_id=? AND status='active'", (uid,)).fetchall()}
    out = []
    for r in rows:
        try:
            data = json.loads(aes_decrypt(skey, r["blob"]))
            mv = mask_val(data.get("value",""))
        except Exception:
            mv = "****"
        out.append({"id": r["id"], "name": r["name"], "cat": r["cat"], "note": r["note"],
                    "mask": mv, "mode": r["mode"], "granted": r["id"] in granted_ids,
                    "model": r["model"] or PROVIDERS.get(r["cat"], {}).get("model", ""),
                    "provider_supported": r["cat"] in PROVIDERS, "created": r["created"]})
    return jsonify(ok=True, mode=t["mode"], keys=out)

@app.route("/api/teams/<int:tid>/keys", methods=["POST"])
@login_required
def create_team_key(tid):
    db = get_db()
    uid = session["uid"]
    t, m, err = _team_key_permission(db, uid, tid, "add")
    if not t: return jsonify(ok=False, err=err), 403
    d = request.get_json(silent=True) or {}
    name = clean_text(d.get("name"), 100)
    value = clean_text(d.get("value"), 4096)
    if not name or not value:
        return jsonify(ok=False, err="名称和密钥内容不能为空")
    cat = d.get("cat") or "其他"
    verr = validate_key_format(cat, value)
    if verr:
        return jsonify(ok=False, err="格式不符: " + verr)
    mode = d.get("mode") or "proxy"
    if mode not in ("proxy", "direct"):
        mode = "proxy"
    if mode == "direct" and not ALLOW_DIRECT_SHARED:
        return jsonify(ok=False, err="公网环境禁止直接下发真实密钥，请使用仅代调用模式"), 403
    model = clean_text(d.get("model"), 120) or PROVIDERS.get(cat, {}).get("model", "")
    if mode == "proxy" and cat not in PROVIDERS and not DEMO_MODE:
        return jsonify(ok=False, err="该分类尚未配置安全的厂商代理地址"), 400
    if mode == "proxy" and not model:
        return jsonify(ok=False, err="请填写调用模型名称"), 400
    blob = aes_encrypt(get_site_key(), json.dumps({"value": value}, ensure_ascii=False))
    now = now_str()
    note = clean_text(d.get("note"), 500)
    cur = db.execute("INSERT INTO shared_keys(name,cat,blob,note,mode,model,created,updated,team_id) VALUES(?,?,?,?,?,?,?,?,?)",
                     (name, cat, blob, note, mode, model, now, now, tid))
    db.commit()
    add_log(uid, "添加团队密钥", f"团队#{tid}:{t['name']}", name)
    return jsonify(ok=True, id=cur.lastrowid)

@app.route("/api/teams/<int:tid>/keys/<int:kid>", methods=["PUT"])
@login_required
def update_team_key(tid, kid):
    db = get_db()
    uid = session["uid"]
    t, m, err = _team_key_permission(db, uid, tid, "edit")
    if not t: return jsonify(ok=False, err=err), 403
    r = db.execute("SELECT * FROM shared_keys WHERE id=? AND team_id=?", (kid, tid)).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    d = request.get_json(silent=True) or {}
    name = clean_text(d.get("name"), 100) or r["name"]
    cat = d.get("cat") or r["cat"]
    value = clean_text(d.get("value"), 4096)
    mode = d.get("mode") or r["mode"]
    if mode not in ("proxy", "direct"):
        mode = r["mode"]
    if mode == "direct" and not ALLOW_DIRECT_SHARED:
        return jsonify(ok=False, err="公网环境禁止直接下发真实密钥，请使用仅代调用模式"), 403
    model = clean_text(d.get("model"), 120) or PROVIDERS.get(cat, {}).get("model", "")
    if mode == "proxy" and cat not in PROVIDERS and not DEMO_MODE:
        return jsonify(ok=False, err="该分类尚未配置安全的厂商代理地址"), 400
    if mode == "proxy" and not model:
        return jsonify(ok=False, err="请填写调用模型名称"), 400
    note = clean_text(d.get("note"), 500)
    data = json.loads(aes_decrypt(get_site_key(), r["blob"]))
    if value:
        verr = validate_key_format(cat, value)
        if verr:
            return jsonify(ok=False, err="格式不符: " + verr)
        data["value"] = value
    blob = aes_encrypt(get_site_key(), json.dumps(data, ensure_ascii=False))
    db.execute("UPDATE shared_keys SET name=?,cat=?,blob=?,note=?,mode=?,model=?,updated=? WHERE id=?",
               (name, cat, blob, note, mode, model, now_str(), kid))
    db.commit()
    action = "轮换团队密钥" if value else "编辑团队密钥"
    detail = f"{name} · 新密钥已加密入库" if value else name
    add_log(uid, action, f"团队#{tid}:{t['name']}", detail)
    return jsonify(ok=True, action=action)

@app.route("/api/teams/<int:tid>/keys/<int:kid>", methods=["DELETE"])
@login_required
def delete_team_key(tid, kid):
    db = get_db()
    uid = session["uid"]
    t, m, err = _team_key_permission(db, uid, tid, "edit")
    if not t: return jsonify(ok=False, err=err), 403
    r = db.execute("SELECT * FROM shared_keys WHERE id=? AND team_id=?", (kid, tid)).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    db.execute("UPDATE virtual_keys SET active=0,revoked_at=? WHERE key_id=? AND active=1", (now_str(), kid))
    db.execute("DELETE FROM shared_keys WHERE id=?", (kid,))
    db.execute("DELETE FROM grants WHERE key_id=?", (kid,))
    db.commit()
    add_log(uid, "删除团队密钥", f"团队#{tid}:{t['name']}", r["name"])
    return jsonify(ok=True)

@app.route("/api/teams/<int:tid>/keys/<int:kid>/grant", methods=["POST"])
@login_required
def grant_team_key(tid, kid):
    """仅班级模式支持领用;科研模式成员资格即授权,无需领用"""
    db = get_db()
    uid = session["uid"]
    t, m, err = _team_key_permission(db, uid, tid, None)
    if not t: return jsonify(ok=False, err=err), 403
    if t["mode"] != "class":
        return jsonify(ok=False, err="科研模式无需领用,成员资格即授权"), 403
    r = db.execute("SELECT * FROM shared_keys WHERE id=? AND team_id=?", (kid, tid)).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    ex = db.execute("SELECT * FROM grants WHERE user_id=? AND key_id=?", (uid, kid)).fetchone()
    if ex and ex["status"] == "active":
        return jsonify(ok=False, err="你已领用该密钥")
    try:
        if ex:
            db.execute("UPDATE grants SET granted_by=?,granted_at=?,status='active' WHERE id=?",
                       (uid, now_str(), ex["id"]))
        else:
            db.execute("INSERT INTO grants(user_id,key_id,granted_by,granted_at,status) VALUES(?,?,?,?,?)",
                       (uid, kid, uid, now_str(), "active"))
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify(ok=False, err="你已领用该密钥"), 409
    add_log(uid, "团队领用", f"团队#{tid}:{t['name']}", r["name"])
    return jsonify(ok=True)

@app.route("/api/teams/<int:tid>/keys/<int:kid>/use", methods=["POST"])
@login_required
def use_team_key(tid, kid):
    """班级模式:需领用;科研模式:成员资格即授权。均走公共代调用实现。"""
    db = get_db()
    uid = session["uid"]
    t, m, err = _team_key_permission(db, uid, tid, None)
    if not t: return jsonify(ok=False, err=err), 403
    r = db.execute("SELECT * FROM shared_keys WHERE id=? AND team_id=?", (kid, tid)).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    if t["mode"] == "class":
        grant = db.execute("SELECT 1 FROM grants WHERE user_id=? AND key_id=? AND status='active'", (uid, kid)).fetchone()
        if not grant:
            return jsonify(ok=False, err="班级模式请先领用该密钥"), 403
    return _proxy_call(uid, r, f"团队#{tid}:{t['name']}", action_success="团队调用", action_fail="团队调用失败")

@app.route("/api/teams/<int:tid>/keys/<int:kid>/reveal", methods=["POST"])
@login_required
def reveal_team_key(tid, kid):
    """仅科研模式支持下发查看(direct 密钥);班级模式一律禁止"""
    db = get_db()
    uid = session["uid"]
    t, m, err = _team_key_permission(db, uid, tid, None)
    if not t: return jsonify(ok=False, err=err), 403
    if t["mode"] == "class":
        return jsonify(ok=False, err="班级模式不支持下发查看,仅可领用代调用"), 403
    if not ALLOW_DIRECT_SHARED:
        return jsonify(ok=False, err="公网环境已禁止直接下发真实密钥"), 403
    r = db.execute("SELECT * FROM shared_keys WHERE id=? AND team_id=?", (kid, tid)).fetchone()
    if not r: return jsonify(ok=False, err="密钥不存在"), 404
    if r["mode"] != "direct":
        return jsonify(ok=False, err="该密钥为「仅代调用」模式,不支持下发查看"), 403
    data = json.loads(aes_decrypt(get_site_key(), r["blob"]))
    add_log(uid, "查看团队密钥", f"团队#{tid}:{t['name']}", r["name"])
    return jsonify(ok=True, value=data.get("value",""), msg="密钥已下发展示")

@app.route("/api/teams/<int:tid>/usage", methods=["GET"])
@login_required
def team_usage(tid):
    """团队用量统计:按团队成员聚合调用次数/Token(不做配额限制)"""
    db = get_db()
    uid = session["uid"]
    t, m, err = _team_key_permission(db, uid, tid, None)
    if not t: return jsonify(ok=False, err=err), 403
    key_count = db.execute("SELECT COUNT(*) FROM shared_keys WHERE team_id=?", (tid,)).fetchone()[0]
    if not key_count:
        return jsonify(ok=True, members=[], summary={"calls": 0, "tokens": 0}, key_count=0)
    rows = db.execute("""SELECT ur.user_id,u.username,
        COUNT(*) AS calls, COALESCE(SUM(ur.total_tokens),0) AS tokens,
        COALESCE(SUM(CASE WHEN ur.status='success' OR ur.status='demo' THEN 1 ELSE 0 END),0) AS successful
        FROM usage_records ur JOIN users u ON u.id=ur.user_id
        JOIN shared_keys sk ON sk.id=ur.key_id
        WHERE sk.team_id=? GROUP BY ur.user_id ORDER BY calls DESC""", (tid,)).fetchall()
    summary = db.execute("""SELECT COUNT(*) AS calls, COALESCE(SUM(ur.total_tokens),0) AS tokens
        FROM usage_records ur JOIN shared_keys sk ON sk.id=ur.key_id WHERE sk.team_id=?""", (tid,)).fetchone()
    return jsonify(ok=True, members=[dict(r) for r in rows],
                   summary={"calls": summary["calls"], "tokens": summary["tokens"]},
                   key_count=key_count)

# ---------------- 成员专属虚拟 Key / OpenAI 兼容入口 ----------------
def virtual_token_hash(token):
    return hmac.new(get_site_key(), b"virtual-key-v1:" + token.encode("utf-8"), sha256).hexdigest()

def _resource_access(db, uid, resource):
    """每次调用重新检查资源、账号、团队成员状态和领用授权。"""
    if not resource or resource["mode"] != "proxy":
        return False, "资源不存在或不支持代理调用", ""
    if resource["team_id"] is None:
        grant = db.execute("""SELECT 1 FROM grants
            WHERE user_id=? AND key_id=? AND status='active'""", (uid, resource["id"])).fetchone()
        return (True, "", "托管密钥:" + resource["name"]) if grant else (False, "资源领用已失效", "")
    team, member, err = _team_key_permission(db, uid, resource["team_id"], None)
    if not team:
        return False, err, ""
    if team["mode"] == "class":
        grant = db.execute("""SELECT 1 FROM grants
            WHERE user_id=? AND key_id=? AND status='active'""", (uid, resource["id"])).fetchone()
        if not grant:
            return False, "班级资源领用已失效", ""
    return True, "", f"团队#{team['id']}:{team['name']}"

def _virtual_key_row(token):
    if not isinstance(token, str) or not token.startswith("ks_") or len(token) > 160:
        return None, "虚拟 Key 格式无效"
    db = get_db()
    row = db.execute("""SELECT vk.*,u.active AS user_active,sk.name AS resource_name,
        sk.cat,sk.mode,sk.model,sk.team_id,sk.blob,sk.note,sk.created AS resource_created,
        sk.updated AS resource_updated
        FROM virtual_keys vk JOIN users u ON u.id=vk.user_id
        JOIN shared_keys sk ON sk.id=vk.key_id WHERE vk.token_hash=?""",
        (virtual_token_hash(token),)).fetchone()
    if not row or not row["active"]:
        return None, "虚拟 Key无效或已撤销"
    if not row["user_active"]:
        return None, "所属账号已停用"
    if row["expires_at"] <= now_str():
        return None, "虚拟 Key已过期"
    return row, ""

def _bearer_virtual_key():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None, "缺少 Bearer 虚拟 Key"
    return _virtual_key_row(auth[7:].strip())

@app.route("/api/virtual-keys", methods=["GET"])
@login_required
def list_virtual_keys():
    uid = session["uid"]
    rows = get_db().execute("""SELECT vk.id,vk.name,vk.token_prefix,vk.created,vk.expires_at,
        vk.daily_limit,vk.active,vk.revoked_at,vk.last_used_at,vk.key_id,
        sk.name AS resource_name,sk.cat,sk.model,sk.team_id,t.name AS team_name
        FROM virtual_keys vk JOIN shared_keys sk ON sk.id=vk.key_id
        LEFT JOIN teams t ON t.id=sk.team_id WHERE vk.user_id=? ORDER BY vk.id DESC""", (uid,)).fetchall()
    now = now_str()
    out = []
    for row in rows:
        item = dict(row)
        item["expired"] = row["expires_at"] <= now
        item["status"] = "revoked" if not row["active"] else "expired" if item["expired"] else "active"
        item["scope"] = row["team_name"] or "学校/企业"
        item["model"] = row["model"] or PROVIDERS.get(row["cat"], {}).get("model", "")
        out.append(item)
    return jsonify(ok=True, virtual_keys=out,
                   base_url=request.url_root.rstrip("/") + "/v1",
                   max_days=VIRTUAL_KEY_MAX_DAYS)

@app.route("/api/virtual-keys", methods=["POST"])
@login_required
def create_virtual_key():
    d = request.get_json(silent=True) or {}
    try:
        key_id = int(d.get("key_id"))
        days = int(d.get("days", 7))
        daily_limit = int(d.get("daily_limit", min(100, DAILY_CALL_LIMIT)))
    except (TypeError, ValueError):
        return jsonify(ok=False, err="资源、有效期或额度格式错误"), 400
    if not 1 <= days <= VIRTUAL_KEY_MAX_DAYS:
        return jsonify(ok=False, err=f"有效期必须为1至{VIRTUAL_KEY_MAX_DAYS}天"), 400
    if not 1 <= daily_limit <= DAILY_CALL_LIMIT:
        return jsonify(ok=False, err=f"每日额度必须为1至{DAILY_CALL_LIMIT}次"), 400
    name = clean_text(d.get("name"), 60) or "开发工具"
    db = get_db(); uid = session["uid"]
    resource = db.execute("SELECT * FROM shared_keys WHERE id=?", (key_id,)).fetchone()
    allowed, err, label = _resource_access(db, uid, resource)
    if not allowed:
        return jsonify(ok=False, err=err), 403
    token = "ks_live_" + secrets.token_urlsafe(32)
    token_prefix = token[:16]
    expires = (datetime.now() + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
    cur = db.execute("""INSERT INTO virtual_keys
        (user_id,key_id,name,token_prefix,token_hash,created,expires_at,daily_limit)
        VALUES(?,?,?,?,?,?,?,?)""",
        (uid, key_id, name, token_prefix, virtual_token_hash(token), now_str(), expires, daily_limit))
    db.commit()
    add_log(uid, "创建虚拟Key", label,
            f"{token_prefix}… · 有效至{expires} · 每日{daily_limit}次")
    model = resource["model"] or PROVIDERS.get(resource["cat"], {}).get("model", "")
    return jsonify(ok=True, id=cur.lastrowid, api_key=token, token_prefix=token_prefix,
                   expires_at=expires, daily_limit=daily_limit, model=model,
                   base_url=request.url_root.rstrip("/") + "/v1",
                   msg="虚拟 Key仅显示一次，请立即保存到系统凭据管理器")

@app.route("/api/virtual-keys/<int:vid>", methods=["DELETE"])
@login_required
def revoke_virtual_key(vid):
    db = get_db(); uid = session["uid"]
    actor = db.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
    row = db.execute("SELECT * FROM virtual_keys WHERE id=?", (vid,)).fetchone()
    if not row or (row["user_id"] != uid and actor["role"] != "admin"):
        return jsonify(ok=False, err="虚拟 Key不存在"), 404
    if not row["active"]:
        return jsonify(ok=False, err="虚拟 Key已经撤销"), 400
    db.execute("UPDATE virtual_keys SET active=0,revoked_at=? WHERE id=?", (now_str(), vid))
    db.commit()
    add_log(uid, "撤销虚拟Key", row["token_prefix"] + "…", f"虚拟Key#{vid}立即失效")
    return jsonify(ok=True)

def _openai_error(message, status=400, code="invalid_request_error"):
    return jsonify(error={"message": message, "type": code, "param": None, "code": code}), status

@app.route("/v1/models", methods=["GET"])
def compatible_models():
    vk, err = _bearer_virtual_key()
    if not vk:
        return _openai_error(err, 401, "invalid_api_key")
    db = get_db(); resource = db.execute("SELECT * FROM shared_keys WHERE id=?", (vk["key_id"],)).fetchone()
    allowed, access_err, _ = _resource_access(db, vk["user_id"], resource)
    if not allowed:
        return _openai_error(access_err, 403, "permission_denied")
    model = resource["model"] or PROVIDERS.get(resource["cat"], {}).get("model", "")
    return jsonify(object="list", data=[{"id": model, "object": "model", "owned_by": "keyshield"}])

@app.route("/v1/chat/completions", methods=["POST"])
def compatible_chat_completions():
    vk, err = _bearer_virtual_key()
    if not vk:
        return _openai_error(err, 401, "invalid_api_key")
    d = request.get_json(silent=True) or {}
    if d.get("stream"):
        return _openai_error("当前版本暂不支持 stream=true", 400, "unsupported_parameter")
    messages = d.get("messages")
    if not isinstance(messages, list) or len(messages) > 100:
        return _openai_error("messages 必须是最多100项的数组")
    parts = []
    for message in messages:
        if not isinstance(message, dict) or message.get("role") not in ("system", "user", "assistant") \
                or not isinstance(message.get("content"), str):
            return _openai_error("当前仅支持文本形式的 system/user/assistant 消息")
        parts.append(f"[{message['role']}] {message['content']}")
    prompt = clean_text("\n".join(parts), 8000)
    if not prompt and not DEMO_MODE:
        return _openai_error("messages 不能为空")
    db = get_db(); resource = db.execute("SELECT * FROM shared_keys WHERE id=?", (vk["key_id"],)).fetchone()
    allowed, access_err, label = _resource_access(db, vk["user_id"], resource)
    if not allowed:
        return _openai_error(access_err, 403, "permission_denied")
    model = resource["model"] or PROVIDERS.get(resource["cat"], {}).get("model", "")
    requested_model = clean_text(d.get("model"), 120)
    if requested_model and requested_model not in (model, "keyshield", "auto"):
        return _openai_error(f"该虚拟 Key仅允许模型 {model}", 403, "model_not_allowed")
    db.execute("UPDATE virtual_keys SET last_used_at=? WHERE id=?", (now_str(), vk["id"]))
    db.commit()
    result = _proxy_call(vk["user_id"], resource, label,
                         action_success="虚拟Key调用", action_fail="虚拟Key调用失败",
                         prompt_override=prompt, virtual_key_id=vk["id"],
                         virtual_daily_limit=vk["daily_limit"])
    if isinstance(result, tuple):
        response, status = result[0], result[1]
    else:
        response, status = result, result.status_code
    data = response.get_json() or {}
    if not data.get("ok"):
        return _openai_error(data.get("err", "上游调用失败"), status,
                             data.get("error_code", "upstream_error"))
    usage = data.get("usage") or {}
    answer = data.get("answer") or data.get("msg") or ""
    return jsonify(id=data["request_id"], object="chat.completion", created=int(time.time()),
                   model=data.get("model") or model,
                   choices=[{"index": 0, "message": {"role": "assistant", "content": answer},
                             "finish_reason": "stop"}],
                   usage={"prompt_tokens": int(usage.get("input_tokens") or 0),
                          "completion_tokens": int(usage.get("output_tokens") or 0),
                          "total_tokens": int(usage.get("total_tokens") or 0)})

# ---------------- 演示数据 ----------------
@app.route("/api/demo", methods=["POST"])
@login_required
def load_demo():
    if not DEMO_MODE:
        return jsonify(ok=False, err="公网环境已关闭演示数据注入"), 403
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["uid"],)).fetchone()
    key = user_crypto_key(u)
    demos = [
        ("DeepSeek API Key","DeepSeek","sk-ds-8f2a1b3c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0","演示数据 · 虚构"),
        ("高德 Web服务 Key","高德","0a5a7d7597e83b0b33a10f16e513024a","演示数据 · 虚构"),
        ("君道AI 生图 Token","君道AI","jd-9c8b7a6d5e4f3g2h1i0j","演示数据 · 虚构"),
        ("Ollama 本地密钥","Ollama","ollama_local_7b_2x","演示数据 · 虚构"),
        ("教务系统账号","校园服务","Cxue@2026#Sec","演示数据 · 虚构"),
    ]
    now = now_str()
    for name, cat, val, note in demos:
        if db.execute("SELECT 1 FROM entries WHERE user_id=? AND name=?", (u["id"], name)).fetchone():
            continue
        blob = aes_encrypt(key, json.dumps({"value": val, "note": note, "expire": "", "history": []}, ensure_ascii=False))
        db.execute("INSERT INTO entries(user_id,name,cat,blob,created,updated) VALUES(?,?,?,?,?,?)",
                   (u["id"], name, cat, blob, now, now))
    db.commit()
    add_log(u["id"], "载入演示数据", "保险箱", "添加 5 条演示密钥(虚构)")
    return jsonify(ok=True, msg="已载入演示密钥")

# ---------------- 启动 ----------------
if __name__ == "__main__":
    app.run(host=os.environ.get("KEYSHIELD_DEV_HOST", "127.0.0.1"), port=8800, debug=False)
