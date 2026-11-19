#!/usr/bin/env bash
# 钥盾 KeyShield · Ubuntu/Debian 生产部署
# 使用前把项目上传到 /opt/keyshield，然后执行：
# sudo KEYSHIELD_DOMAIN=keys.example.edu.cn KEYSHIELD_EMAIL=ops@example.edu.cn bash deploy/deploy.sh
set -Eeuo pipefail

APP_DIR="/opt/keyshield"
DATA_DIR="/var/lib/keyshield"
SERVICE_NAME="keyshield"
SERVICE_USER="keyshield"
DOMAIN="${KEYSHIELD_DOMAIN:-_}"
EMAIL="${KEYSHIELD_EMAIL:-}"
PUBLIC_HOST="${KEYSHIELD_PUBLIC_HOST:-}"
if [ -n "${KEYSHIELD_COOKIE_SECURE:-}" ]; then
  COOKIE_SECURE="$KEYSHIELD_COOKIE_SECURE"
elif [ "$DOMAIN" != "_" ] && [ -n "$EMAIL" ]; then
  COOKIE_SECURE=1
else
  COOKIE_SECURE=0
fi
if [ "$COOKIE_SECURE" != "0" ] && [ "$COOKIE_SECURE" != "1" ]; then
  echo "KEYSHIELD_COOKIE_SECURE 只能设置为 0 或 1。" >&2
  exit 1
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "请使用 sudo/root 执行部署脚本。" >&2
  exit 1
fi

echo "==> [1/8] 安装 Python、Nginx、证书和备份依赖"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
  python3 python3-pip python3-venv nginx certbot python3-certbot-nginx sqlite3 curl >/dev/null

echo "==> [2/8] 校验代码与创建低权限运行账号"
for required in app.py admin_setup.py requirements.txt templates/index.html; do
  if [ ! -f "$APP_DIR/$required" ]; then
    echo "缺少 $APP_DIR/$required，请先完整上传项目。" >&2
    exit 1
  fi
done
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  useradd --system --home-dir "$DATA_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$DATA_DIR" "$DATA_DIR/backups"

echo "==> [3/8] 建立隔离虚拟环境并安装锁定范围内的依赖"
if [ ! -x "$APP_DIR/.venv/bin/python" ]; then
  python3 -m venv "$APP_DIR/.venv"
fi
"$APP_DIR/.venv/bin/pip" install --quiet --upgrade pip
"$APP_DIR/.venv/bin/pip" install --quiet -r "$APP_DIR/requirements.txt"

echo "==> [4/8] 无损迁移旧部署数据并初始化数据库"
for item in keyshield.db .site_key .flask_secret .audit_anchor; do
  if [ -e "$APP_DIR/$item" ]; then
    if [ ! -e "$DATA_DIR/$item" ]; then
      cp -a "$APP_DIR/$item" "$DATA_DIR/$item"
    fi
    rm -f -- "$APP_DIR/$item"
  fi
done
cd "$APP_DIR"
KEYSHIELD_ENV=production KEYSHIELD_DATA_DIR="$DATA_DIR" \
  "$APP_DIR/.venv/bin/python" -c "from app import init_db, get_site_key; init_db(); get_site_key(); print('数据库与站点密钥 OK')"

echo "==> [5/8] 首个管理员安全初始化（只在服务器终端进行）"
KEYSHIELD_ENV=production KEYSHIELD_DATA_DIR="$DATA_DIR" \
  "$APP_DIR/.venv/bin/python" "$APP_DIR/admin_setup.py"
chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
chmod 0750 "$DATA_DIR" "$DATA_DIR/backups"
chmod 0600 "$DATA_DIR/keyshield.db" "$DATA_DIR/.site_key" "$DATA_DIR/.flask_secret" "$DATA_DIR/.audit_anchor"
chown -R root:root "$APP_DIR/app.py" "$APP_DIR/admin_setup.py" "$APP_DIR/requirements.txt" "$APP_DIR/templates" "$APP_DIR/deploy"

echo "==> [6/8] 注册受限 systemd 服务（应用端口不暴露公网）"
install -d -o root -g root -m 0750 /etc/keyshield
cat > /etc/keyshield/keyshield.env <<EOF
KEYSHIELD_ENV=production
KEYSHIELD_DEMO_MODE=0
KEYSHIELD_REQUIRE_INVITE=0
KEYSHIELD_ALLOW_DIRECT=0
KEYSHIELD_DEMO_BILLING=0
KEYSHIELD_TRUST_PROXY=1
KEYSHIELD_COOKIE_SECURE=$COOKIE_SECURE
KEYSHIELD_EMAIL_MODE=smtp
KEYSHIELD_EMAIL_STEP_UP=1
KEYSHIELD_DATA_DIR=$DATA_DIR
KEYSHIELD_DAILY_CALL_LIMIT=100
KEYSHIELD_MAX_OUTPUT_TOKENS=1024
KEYSHIELD_VIRTUAL_KEY_MAX_DAYS=90
EOF
chmod 0600 /etc/keyshield/keyshield.env
cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=KeyShield campus AI secret management platform
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=/etc/keyshield/keyshield.env
ExecStart=$APP_DIR/.venv/bin/waitress-serve --host=127.0.0.1 --port=8800 --threads=8 app:app
Restart=on-failure
RestartSec=3
TimeoutStopSec=20
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
ReadWritePaths=$DATA_DIR

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now "$SERVICE_NAME"

echo "==> [7/8] 配置 Nginx 反向代理、请求大小和基础限流"
cat > /etc/nginx/conf.d/keyshield_limits.conf <<'EOF'
limit_req_zone $binary_remote_addr zone=keyshield_api:10m rate=10r/s;
EOF
cat > /etc/nginx/sites-available/keyshield <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    client_max_body_size 64k;

    location /api/ {
        limit_req zone=keyshield_api burst=30 nodelay;
        proxy_pass http://127.0.0.1:8800;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_connect_timeout 10s;
        proxy_read_timeout 45s;
    }

    location / {
        proxy_pass http://127.0.0.1:8800;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
ln -sfn /etc/nginx/sites-available/keyshield /etc/nginx/sites-enabled/keyshield
rm -f /etc/nginx/sites-enabled/default
nginx -t
systemctl reload nginx

echo "==> [8/8] 配置 HTTPS 与验证健康状态"
if [ "$DOMAIN" != "_" ] && [ -n "$EMAIL" ]; then
  certbot --nginx --non-interactive --agree-tos --redirect --hsts \
    --email "$EMAIL" -d "$DOMAIN"
  PUBLIC_URL="https://$DOMAIN"
else
  if [ -n "$PUBLIC_HOST" ]; then
    PUBLIC_URL="http://$PUBLIC_HOST"
  else
    PUBLIC_URL="http://$(hostname -I | awk '{print $1}')"
  fi
  echo "警告：未提供 KEYSHIELD_DOMAIN/KEYSHIELD_EMAIL，目前只有 HTTP，不应开放给真实用户。" >&2
fi

HEALTHY=0
for _attempt in $(seq 1 30); do
  if curl --fail --silent http://127.0.0.1:8800/api/health >/dev/null; then
    HEALTHY=1
    break
  fi
  sleep 1
done
if [ "$HEALTHY" -ne 1 ]; then
  echo "KeyShield 在 30 秒内未通过健康检查。" >&2
  systemctl --no-pager -l status "$SERVICE_NAME" >&2 || true
  journalctl -u "$SERVICE_NAME" -n 80 --no-pager >&2 || true
  exit 1
fi
install -o root -g root -m 0750 "$APP_DIR/deploy/backup.sh" /usr/local/sbin/keyshield-backup
cat > /etc/systemd/system/keyshield-backup.service <<'EOF'
[Unit]
Description=KeyShield encrypted data backup

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/keyshield-backup
EOF
cat > /etc/systemd/system/keyshield-backup.timer <<'EOF'
[Unit]
Description=Run KeyShield backup every day

[Timer]
OnCalendar=*-*-* 03:15:00
Persistent=true
RandomizedDelaySec=15m

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
systemctl enable --now keyshield-backup.timer

echo ""
echo "====================================================="
echo "部署完成：$PUBLIC_URL"
echo "服务状态：systemctl status $SERVICE_NAME"
echo "服务日志：journalctl -u $SERVICE_NAME -n 100 --no-pager"
echo "手工备份：sudo keyshield-backup"
echo "重要：只在云安全组开放 80/443，不要开放 8800。"
echo "====================================================="
