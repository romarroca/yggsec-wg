#!/usr/bin/env bash
# YggSec permissions/bootstrap for networking helpers
# Idempotent. Safe to re-run.
set -euo pipefail

APP_DIR="${APP_DIR:-/opt/yggsec}"
APP_USER="${APP_USER:-yggsec}"
WG_IFACE="${WG_IFACE:-wg0}"

echo "[perm] setcaps for wg/ip/nft/conntrack"
for b in /usr/bin/wg /usr/bin/wg-quick /usr/bin/ip; do
  [ -x "$b" ] && sudo setcap cap_net_admin,cap_net_raw+ep "$b" || true
done
for b in /usr/sbin/nft /usr/sbin/iptables /usr/sbin/ip6tables /usr/sbin/conntrack; do
  [ -x "$b" ] && sudo setcap cap_net_admin+ep "$b" || true
done

echo "[perm] systemd helper unit for wg-quick"
sudo tee /etc/systemd/system/wg-up@.service >/dev/null <<'UNIT'
[Unit]
Description=wg-quick up %I
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=root
ExecStartPre=-/usr/bin/wg-quick down %I
ExecStart=/usr/bin/wg-quick up %I
ExecStop=/usr/bin/wg-quick down %I
RemainAfterExit=yes
UNIT

echo "[perm] polkit rule: allow yggsec to manage wg-up@*.service"
sudo tee /etc/polkit-1/rules.d/50-yggsec-wg.rules >/dev/null <<'PR'
polkit.addRule(function(action, subject) {
  if (action.id == "org.freedesktop.systemd1.manage-units" &&
      subject.user == "yggsec" &&
      action.lookup("unit") &&
      action.lookup("unit").match(/^wg-up@.*\.service$/)) {
    return polkit.Result.YES;
  }
});
PR

echo "[perm] config locations and perms"
# Ensure APP_DIR is accessible by root (755) while keeping sensitive dirs restricted
sudo chmod 755 "$APP_DIR"
sudo install -d -m 0755 "$APP_DIR/configs" /etc/wireguard
# Create placeholder config file with proper permissions
sudo touch "$APP_DIR/configs/${WG_IFACE}.conf"
sudo chown "$APP_USER:$APP_USER" "$APP_DIR/configs/${WG_IFACE}.conf"
sudo chmod 644 "$APP_DIR/configs/${WG_IFACE}.conf"

# Create symlink from /etc/wireguard/ to configs/ for dynamic updates
sudo ln -sf "$APP_DIR/configs/${WG_IFACE}.conf" "/etc/wireguard/${WG_IFACE}.conf"
sudo chown root:root "/etc/wireguard/${WG_IFACE}.conf"
sudo chmod 600 "/etc/wireguard/${WG_IFACE}.conf"

# Create topology.json if it doesn't exist
if [ ! -f "$APP_DIR/topology.json" ]; then
  echo '{}' | sudo tee "$APP_DIR/topology.json" >/dev/null
fi
sudo chown "$APP_USER:$APP_USER" "$APP_DIR/topology.json"
sudo chmod 644 "$APP_DIR/topology.json"

# Set proper ownership for the entire app directory
sudo chown -R "$APP_USER:$APP_USER" "$APP_DIR"

echo "[perm] reload daemons"
sudo systemctl daemon-reload
sudo systemctl restart polkit || true

echo "[perm] quick test (optional)"
sudo systemctl restart "wg-up@${WG_IFACE}" || true
sudo systemctl status "wg-up@${WG_IFACE}" --no-pager || true

echo "[perm] done"

