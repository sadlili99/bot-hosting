#!/usr/bin/env bash
# 梨园托管台 · 云服务器一键部署（Linux + systemd）
# 用法（root）： curl -fsSL https://raw.githubusercontent.com/sadlili99/bot-hosting/main/deploy.sh | bash
set -euo pipefail

DEST=/opt/bot-hosting
TARBALL=https://codeload.github.com/sadlili99/bot-hosting/tar.gz/refs/heads/main

echo "==> 检查 Python 3"
if ! command -v python3 >/dev/null 2>&1; then
  echo "未发现 python3，尝试安装…"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y && apt-get install -y python3 curl
  elif command -v yum >/dev/null 2>&1; then
    yum install -y python3 curl
  else
    echo "无法自动安装 python3，请先手动安装后重试" >&2; exit 1
  fi
fi
python3 --version

echo "==> 拉取代码到 $DEST"
mkdir -p "$DEST"
TMP=$(mktemp -d)
curl -fsSL "$TARBALL" -o "$TMP/src.tgz"
tar -xzf "$TMP/src.tgz" -C "$TMP"
cp -a "$TMP"/bot-hosting-main/. "$DEST"/
rm -rf "$TMP"
ls "$DEST"

echo "==> 写入 systemd 服务"
cat > /etc/systemd/system/liyuan-bot-host.service <<'UNIT'
[Unit]
Description=Liyuan Bot Host
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/opt/bot-hosting
Environment=PORT=8080
ExecStart=/usr/bin/python3 /opt/bot-hosting/server.py
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable liyuan-bot-host.service
systemctl restart liyuan-bot-host.service

echo "==> 健康检查"
for i in $(seq 1 15); do
  if curl -fsS http://127.0.0.1:8080/api/health; then
    echo; echo "部署完成：服务已启动（8080）"; exit 0
  fi
  sleep 1
done
echo "服务未通过健康检查，最近日志：" >&2
journalctl -u liyuan-bot-host.service -n 30 --no-pager >&2 || true
exit 1
