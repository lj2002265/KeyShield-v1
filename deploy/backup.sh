#!/usr/bin/env bash
# 一致性备份：数据库、加密根密钥、会话签名密钥和数据库外审计锚点必须成套保存。
set -Eeuo pipefail

DATA_DIR="${KEYSHIELD_DATA_DIR:-/var/lib/keyshield}"
BACKUP_DIR="$DATA_DIR/backups"
STAMP="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="$BACKUP_DIR/keyshield-$STAMP.tar.gz"
TMP_DIR="$(mktemp -d "$BACKUP_DIR/.backup.XXXXXX")"
trap 'rm -rf -- "$TMP_DIR"' EXIT

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo 执行备份。" >&2
  exit 1
fi
for required in keyshield.db .site_key .flask_secret .audit_anchor; do
  if [ ! -f "$DATA_DIR/$required" ]; then
    echo "缺少 $DATA_DIR/$required，备份中止。" >&2
    exit 1
  fi
done

sqlite3 "$DATA_DIR/keyshield.db" ".backup '$TMP_DIR/keyshield.db'"
install -m 0600 "$DATA_DIR/.site_key" "$TMP_DIR/.site_key"
install -m 0600 "$DATA_DIR/.flask_secret" "$TMP_DIR/.flask_secret"
install -m 0600 "$DATA_DIR/.audit_anchor" "$TMP_DIR/.audit_anchor"
tar -C "$TMP_DIR" -czf "$ARCHIVE" keyshield.db .site_key .flask_secret .audit_anchor
chmod 0600 "$ARCHIVE"
find "$BACKUP_DIR" -maxdepth 1 -type f -name 'keyshield-*.tar.gz' -mtime +14 -delete
echo "备份完成：$ARCHIVE"
