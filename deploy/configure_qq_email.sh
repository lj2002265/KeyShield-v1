#!/usr/bin/env bash
# 在服务器终端安全配置 QQ 邮箱 SMTP；授权码输入不回显。
set -Eeuo pipefail

ENV_FILE="${KEYSHIELD_ENV_FILE:-/etc/keyshield/keyshield.env}"
SERVICE_NAME="${KEYSHIELD_SERVICE_NAME:-keyshield}"

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo bash $0 执行。" >&2
  exit 1
fi
if [ ! -f "$ENV_FILE" ]; then
  echo "未找到 $ENV_FILE，请先完成 KeyShield 部署。" >&2
  exit 1
fi

read -r -p "QQ 发件邮箱（完整地址）: " smtp_user
if ! printf '%s' "$smtp_user" | grep -Eq '^[^[:space:]@]+@(qq|foxmail)\.com$'; then
  echo "请输入有效的 @qq.com 或 @foxmail.com 邮箱地址。" >&2
  exit 1
fi

read -r -s -p "QQ SMTP 授权码（输入不会显示）: " smtp_password
printf '\n'
if ! printf '%s' "$smtp_password" | grep -Eq '^[A-Za-z0-9]{16,64}$'; then
  unset smtp_password
  echo "授权码格式不正确；请使用 QQ 邮箱生成的 SMTP 授权码，不要使用登录密码。" >&2
  exit 1
fi

umask 077
tmp_file="$(mktemp /tmp/keyshield-email.XXXXXX)"
trap 'rm -f -- "$tmp_file"; unset smtp_password' EXIT

grep -vE '^(KEYSHIELD_EMAIL_MODE|KEYSHIELD_SMTP_HOST|KEYSHIELD_SMTP_PORT|KEYSHIELD_SMTP_USER|KEYSHIELD_SMTP_PASSWORD|KEYSHIELD_SMTP_FROM|KEYSHIELD_SMTP_SSL|KEYSHIELD_SMTP_STARTTLS)=' "$ENV_FILE" > "$tmp_file"
printf '%s\n' \
  'KEYSHIELD_EMAIL_MODE=smtp' \
  'KEYSHIELD_SMTP_HOST=smtp.qq.com' \
  'KEYSHIELD_SMTP_PORT=465' \
  "KEYSHIELD_SMTP_USER=$smtp_user" \
  "KEYSHIELD_SMTP_PASSWORD=$smtp_password" \
  "KEYSHIELD_SMTP_FROM=$smtp_user" \
  'KEYSHIELD_SMTP_SSL=1' \
  'KEYSHIELD_SMTP_STARTTLS=0' >> "$tmp_file"

cat "$tmp_file" > "$ENV_FILE"
chmod 0600 "$ENV_FILE"
unset smtp_password
systemctl restart "$SERVICE_NAME"
sleep 2
systemctl is-active --quiet "$SERVICE_NAME"
curl -fsS http://127.0.0.1:8800/api/health >/dev/null

echo "QQ 邮箱配置已保存，KeyShield 服务健康。请回到注册页发送一封验证码进行最终验证。"
