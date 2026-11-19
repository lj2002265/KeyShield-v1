#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""钥盾首个管理员安全初始化/零管理员恢复工具。仅在服务器终端/SSH 中执行。"""
import argparse
import getpass
import io
import re
import sqlite3
import sys

from werkzeug.security import generate_password_hash

from app import (DB_PATH, add_log, build_user_key_material, init_db, now_str,
                 reconcile_unhashed_audit_tail, verify_audit_chain)

if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

PHONE_RE = re.compile(r"^1[3-9]\d{9}$")

def parse_args():
    parser = argparse.ArgumentParser(description="钥盾首个管理员初始化与零管理员恢复")
    parser.add_argument("--promote-existing", metavar="USERNAME",
                        help="仅当系统不存在管理员时，将一个已启用的现有账户恢复为管理员")
    parser.add_argument("--confirm-zero-admin-recovery", action="store_true",
                        help="确认正在本机/SSH 执行零管理员恢复（便于自动化部署）")
    parser.add_argument("--reconcile-unhashed-audit-tail", action="store_true",
                        help="显式接管升级时旧进程留下的未哈希日志尾部")
    return parser.parse_args()


def main():
    args = parse_args()
    init_db()
    if args.reconcile_unhashed_audit_tail:
        repaired = reconcile_unhashed_audit_tail()
        print(f"✅ 已将 {repaired} 条未哈希尾部日志接入审计链。")
    db = sqlite3.connect(DB_PATH)
    try:
        db.execute("BEGIN IMMEDIATE")
        if db.execute("SELECT 1 FROM users WHERE role='admin' LIMIT 1").fetchone():
            db.rollback()
            print("管理员已存在,初始化已取消。后续管理员请在钥盾用户管理中授权。")
            return 0

        if args.promote_existing:
            target = db.execute(
                "SELECT id,username,role,active FROM users WHERE username=?",
                (args.promote_existing.strip(),),
            ).fetchone()
            if not target:
                raise ValueError("未找到指定账户")
            if not target[3]:
                raise ValueError("指定账户已停用，请先恢复账户状态")
            integrity = verify_audit_chain()
            if not integrity["ok"]:
                raise ValueError("审计链完整性异常，拒绝提升权限:" + integrity["reason"])
            if not args.confirm_zero_admin_recovery:
                phrase = input(f"输入 PROMOTE {target[1]} 确认恢复管理员: ").strip()
                if phrase != f"PROMOTE {target[1]}":
                    raise ValueError("确认短语不匹配")
            db.execute("UPDATE users SET role='admin' WHERE id=?", (target[0],))
            db.commit()
            try:
                add_log(None, "SSH恢复管理员", target[1],
                        "系统无管理员时由本机/SSH操作员执行；目标账户原为普通用户")
            except Exception:
                db.execute("UPDATE users SET role=? WHERE id=?", (target[2], target[0]))
                db.commit()
                raise
            print(f"✅ 账户 {target[1]} 已恢复为管理员，并已写入审计日志。")
            return 0

        print("═══ 钥盾 KeyShield · 首个管理员初始化 ═══")
        username = input("管理员用户名: ").strip()
        phone = input("管理员手机号: ").strip()
        password = getpass.getpass("管理员密码(至少10位): ")
        confirm = getpass.getpass("再次输入密码: ")
        if len(username) < 2:
            raise ValueError("用户名至少2位")
        if not PHONE_RE.fullmatch(phone):
            raise ValueError("手机号格式不正确")
        if len(password) < 10:
            raise ValueError("管理员密码至少10位")
        if password != confirm:
            raise ValueError("两次输入的密码不一致")
        if db.execute("SELECT 1 FROM users WHERE username=? OR phone=?", (username, phone)).fetchone():
            raise ValueError("用户名或手机号已被使用")

        salt, _, wrapped_key = build_user_key_material(password)
        db.execute("""INSERT INTO users(username,pw_hash,salt,role,active,phone,wrapped_key,created)
                      VALUES(?,?,?,'admin',1,?,?,?)""",
                   (username, generate_password_hash(password), salt, phone, wrapped_key, now_str()))
        db.commit()
        print("✅ 首个管理员创建成功。现在可以启动公网服务。")
        return 0
    except (ValueError, EOFError, KeyboardInterrupt) as exc:
        db.rollback()
        print(f"❌ 初始化失败:{exc}", file=sys.stderr)
        return 1
    finally:
        db.close()

if __name__ == "__main__":
    raise SystemExit(main())
