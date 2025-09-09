#!/usr/bin/env bash
# YggSec init — fresh, least-privilege install
# Usage: sudo ./init.sh [APP_DIR]   # default /opt/yggsec
set -euo pipefail

# Comprehensive installation prompt and instructions
echo "============================================================"
echo "               YggSec WG Installation Setup"
echo "============================================================"
echo ""
echo "BEFORE PROCEEDING, PLEASE READ THE FOLLOWING INSTRUCTIONS:"
echo ""
echo "SYSTEM REQUIREMENTS:"
echo "• Ubuntu 20.04+ or Debian 11+ (recommended: Ubuntu 24.04)"
echo "• Root/sudo access required"
echo "• Minimum 1GB RAM, 2GB disk space"
echo "• Internet connection for package downloads (~200MB)"
echo ""
echo "WHAT THIS INSTALLATION WILL DO:"
echo "• Install WireGuard VPN, nftables firewall, Suricata IPS"
echo "• Create yggsec system user and service"
echo "• Configure nginx reverse proxy on port 80"
echo "• Set up systemd service for automatic startup"
echo "• Install Python dependencies and web interface"
echo "• Configure network interfaces and firewall rules"
echo ""
echo "INSTALLATION PROCESS:"
echo "• Duration: 3-10 minutes (depending on network speed)"
echo "• Downloads: ~200MB of packages from Ubuntu/Debian repositories"
echo "• Creates files in: ${1:-/opt/yggsec}, /var/log/yggsec, /etc/systemd/system"
echo "• Modifies: /etc/nginx/, network configuration"
echo ""
echo "IMPORTANT WARNINGS:"
echo "⚠️  DO NOT INTERRUPT this installation once started"
echo "⚠️  Interruption may leave system in inconsistent state"
echo "⚠️  Ensure stable network connection before proceeding"
echo "⚠️  This will modify system network and firewall settings"
echo "⚠️  Have console/physical access available in case of issues"
echo ""
echo "POST-INSTALLATION:"
echo "• Access web interface at: https://YOUR_SERVER_IP"
echo "• Default login will be provided at end of installation"
echo "• Configure WireGuard VPN through web interface"
echo "• Review firewall rules and adjust as needed"
echo ""
echo "============================================================"
echo ""
echo "By proceeding, you acknowledge that you have:"
echo "✓ Read and understood the above requirements and warnings"
echo "✓ Verified this server meets the system requirements"
echo "✓ Ensured you have stable network connectivity"
echo "✓ Have console/physical access to this server if needed"
echo "✓ Made appropriate backups of existing configurations"
echo ""
read -p "Press ENTER to acknowledge and proceed with installation, or Ctrl+C to cancel: "
echo ""
echo "============================================================"
echo "            YggSec Installation - STARTING"
echo "============================================================"
echo "Installing to: ${1:-/opt/yggsec}"
echo "Please wait for completion - this may take several minutes..."
echo "============================================================"
echo ""

# Handle Ctrl+C gracefully with warning
trap 'echo -e "\nWARNING: Installation interrupted! System may be in inconsistent state."; echo "Run this script again to complete installation."; exit 1' INT

APP_DIR="${1:-/opt/yggsec}"
APP_USER="yggsec"
APP_GROUP="$APP_USER"
SRC_DIR="$(pwd)"
VENV_DIR="$APP_DIR/venv"
SVC_NAME="yggsec.service"
LOG_DIR="/var/log/yggsec"
NETPLAN_FILE="/etc/netplan/01-yggsec.yaml"
BACKUP_DIR="/root/yggsec-backups"

echo "[1/10] Install packages (2-5 minutes - please wait, DO NOT INTERRUPT)"
export DEBIAN_FRONTEND=noninteractive

echo "Updating package lists..."
apt-get update -y

echo "Installing core packages (WireGuard, nginx, Suricata IPS)..."
echo "    This step downloads ~200MB and may take several minutes"

apt-get install -y \
  python3-venv python3-pip rsync jq \
  wireguard-tools nftables suricata suricata-update \
  netplan.io iputils-ping net-tools \
  openssh-client openssh-server \
  nginx openssl \
  conntrack

if [ $? -eq 0 ]; then
  echo "[OK] Package installation complete - all dependencies installed successfully"
else
  echo "[ERROR] Package installation failed - check network connection and try again"
  exit 1
fi

echo "[2/10] Create user and dirs"
id -u "$APP_USER" &>/dev/null || useradd -r -s /usr/sbin/nologin -d "$APP_DIR" "$APP_USER"
mkdir -p "$APP_DIR" "$LOG_DIR" /etc/nftables.d /etc/netplan "$BACKUP_DIR" "$APP_DIR/cache"
chown -R "$APP_USER:$APP_GROUP" "$APP_DIR" "$LOG_DIR"
chmod 750 "$APP_DIR"

# Ensure /run/wireguard exists on every boot (tmpfiles.d)
printf 'd /run/wireguard 0755 root root -\n' | tee /etc/tmpfiles.d/wireguard.conf >/dev/null
systemd-tmpfiles --create /etc/tmpfiles.d/wireguard.conf

# ---- Clean deploy block: stop, backup, wipe, redeploy ----
echo "[3/10] Stop service, backup state, wipe target, and deploy fresh (30 seconds)"
# 3a) stop running service if present
echo "Checking for existing services..."
if systemctl list-unit-files | grep -q "^$SVC_NAME"; then
  echo "Stopping existing yggsec service..."
  systemctl stop "$SVC_NAME" || true
fi

# 3b) backup previous configs/keys (keep last 5)
if [ -d "$APP_DIR" ]; then
  tar czf "$BACKUP_DIR/$(date +%F-%H%M%S).tgz" \
    --ignore-failed-read \
    "$APP_DIR/configs" "$APP_DIR/keys" 2>/dev/null || true
  ls -1t "$BACKUP_DIR"/*.tgz 2>/dev/null | tail -n +6 | xargs -r rm -f
fi

# 3c) wipe contents of APP_DIR (keep the dir)
if [ -d "$APP_DIR" ]; then
  find "$APP_DIR" -mindepth 1 -maxdepth 1 -exec rm -rf {} +
else
  mkdir -p "$APP_DIR"
fi
chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"

# 3d) deploy fresh code
if command -v rsync >/dev/null 2>&1; then
  rsync -a --delete --exclude 'venv/' --exclude '__pycache__/' "$SRC_DIR"/ "$APP_DIR"/
else
  cp -a "$SRC_DIR"/. "$APP_DIR"/
fi
chown -R "$APP_USER:$APP_GROUP" "$APP_DIR"

echo "[4/10] Python venv + deps (1-2 minutes)"
echo "Setting up Python virtual environment..."
python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/pip" install --upgrade pip wheel
if [ -f "$APP_DIR/requirements.txt" ]; then
  echo "Installing Python dependencies (Flask, security tools)..."
  "$VENV_DIR/bin/pip" install -r "$APP_DIR/requirements.txt"
fi
"$VENV_DIR/bin/pip" show gunicorn >/dev/null 2>&1 || "$VENV_DIR/bin/pip" install gunicorn
echo "[OK] Python environment ready"

echo "[5/10] Network setup"
# Enumerate non-loopback, non-WireGuard interfaces
mapfile -t IFACES < <(ip -o link show | awk -F': ' '$2!="lo" && $2!~/^wg[0-9]+$/{print $2}')
if [ ${#IFACES[@]} -eq 0 ]; then
  echo "No network interfaces found. Abort."
  exit 1
fi

echo "Found interfaces:"
for i in "${!IFACES[@]}"; do 
    IFACE_IP=$(ip addr show "${IFACES[$i]}" 2>/dev/null | grep -E "inet [0-9]+\." | grep -v "127\." | head -1 | awk '{print $2}' | cut -d'/' -f1)
    printf "  [%d] %s (%s)\n" "$i" "${IFACES[$i]}" "${IFACE_IP:-no IP}"
done

# Pick OUTSIDE/WAN
while :; do
  read -p "Select OUTSIDE interface index: " IDX || {
    echo -e "\nSetup cancelled by user."
    exit 1
  }
  [[ "$IDX" =~ ^[0-9]+$ ]] && [[ $IDX -ge 0 && $IDX -lt ${#IFACES[@]} ]] && break
  echo "Invalid index."
done
NET_IFACE="${IFACES[$IDX]}"
echo "Selected OUTSIDE: $NET_IFACE"

# Optional LAN
read -p "Configure a LAN interface too? [y/N]: " CFG_LAN || {
  echo -e "\nSetup cancelled by user."
  exit 1
}
LAN_IFACE=""
if [[ "$CFG_LAN" =~ ^[Yy]$ ]]; then
  while :; do
    read -p "Select LAN interface index (not $NET_IFACE): " LIDX || {
      echo -e "\nSetup cancelled by user."
      exit 1
    }
    [[ "$LIDX" =~ ^[0-9]+$ ]] && [[ $LIDX -ge 0 && $LIDX -lt ${#IFACES[@]} ]] && [[ "${IFACES[$LIDX]}" != "$NET_IFACE" ]] && break
    echo "Invalid index."
  done
  LAN_IFACE="${IFACES[$LIDX]}"
  echo "Selected LAN: $LAN_IFACE"
fi

# Management interface selection
echo ""
echo "Configure management web interface (HTTPS port 443):"
echo "Available interfaces:"
for i in "${!IFACES[@]}"; do 
    IFACE_IP=$(ip addr show "${IFACES[$i]}" 2>/dev/null | grep -E "inet [0-9]+\." | grep -v "127\." | head -1 | awk '{print $2}' | cut -d'/' -f1)
    printf "  [%d] %s (%s)\n" "$i" "${IFACES[$i]}" "${IFACE_IP:-no IP}"
done
echo "  [A] All interfaces (0.0.0.0)"

echo ""
echo "WARNING: Selecting OUTSIDE interface ($NET_IFACE) will expose management"
echo "         to the internet on port 443. This may pose security risks."
echo "         Consider using LAN interface for better security."
echo ""

while :; do
  read -p "Select management interface [0-$((${#IFACES[@]}-1)), A]: " MGMT_IDX || {
    echo -e "\nSetup cancelled by user."
    exit 1
  }
  if [[ "$MGMT_IDX" =~ ^[Aa]$ ]]; then
    MGMT_IFACE="all"
    echo "Management access: All interfaces (0.0.0.0:443)"
    break
  elif [[ "$MGMT_IDX" =~ ^[0-9]+$ ]] && [[ $MGMT_IDX -ge 0 && $MGMT_IDX -lt ${#IFACES[@]} ]]; then
    MGMT_IFACE="${IFACES[$MGMT_IDX]}"
    echo "Management access: $MGMT_IFACE interface only"
    break
  else
    echo "Invalid selection."
  fi
done

# Store management interface choice for later nginx configuration
echo "MGMT_IFACE=\"$MGMT_IFACE\"" > /tmp/yggsec_mgmt_access.conf
echo "NET_IFACE=\"$NET_IFACE\"" >> /tmp/yggsec_mgmt_access.conf
echo "LAN_IFACE=\"$LAN_IFACE\"" >> /tmp/yggsec_mgmt_access.conf

# Backup existing netplan once
if [ ! -f /etc/netplan/.yggsec.bak.done ]; then
  tar -czf /etc/netplan/netplan-backup.$(date +%s).tgz /etc/netplan/*.yaml 2>/dev/null || true
  touch /etc/netplan/.yggsec.bak.done
fi

# DHCP or static for OUTSIDE
read -p "Use DHCP for $NET_IFACE? [y/N]: " USE_DHCP || {
  echo -e "\nSetup cancelled by user."
  exit 1
}

if [[ "$USE_DHCP" =~ ^[Yy]$ ]]; then
  cat > "$NETPLAN_FILE" <<EOF
network:
  version: 2
  ethernets:
    $NET_IFACE:
      dhcp4: true
$( [[ -n "$LAN_IFACE" ]] && cat <<LAN
    $LAN_IFACE:
      dhcp4: false
      addresses: [192.168.50.1/24]
LAN
)
EOF
  chmod 600 "$NETPLAN_FILE"
else
  read -p "Enter static IP for $NET_IFACE (e.g. 192.168.1.10/24): " STATIC_IP || {
    echo -e "\nSetup cancelled by user."
    exit 1
  }
  read -p "Enter gateway for $NET_IFACE (e.g. 192.168.1.1): " GW || {
    echo -e "\nSetup cancelled by user."
    exit 1
  }
  read -p "Enter DNS servers (comma separated, e.g. 1.1.1.1,8.8.8.8): " DNS || {
    echo -e "\nSetup cancelled by user."
    exit 1
  }
  cat > "$NETPLAN_FILE" <<EOF
network:
  version: 2
  ethernets:
    $NET_IFACE:
      dhcp4: false
      addresses:
        - $STATIC_IP
      routes:
        - to: default
          via: $GW
      nameservers:
        addresses: [${DNS// /}]
$( [[ -n "$LAN_IFACE" ]] && cat <<LAN
    $LAN_IFACE:
      dhcp4: false
      addresses: [192.168.50.1/24]
LAN
)
EOF
  chmod 600 "$NETPLAN_FILE"
fi

echo "[*] Applying network configuration (10-30 seconds - DO NOT INTERRUPT)"
echo "WARNING: Network reconfiguration in progress - connection may briefly drop"
# Ensure spaces only in YAML (no tabs)
if grep -P "\t" "$NETPLAN_FILE" >/dev/null 2>&1; then
  echo "Error: Tabs found in $NETPLAN_FILE. Replace with spaces."
  exit 1
fi
netplan generate && netplan apply || echo "Warning: netplan apply failed, check $NETPLAN_FILE."
echo "[OK] Network configuration applied"


echo "[7/10] Systemd unit"
# Generate secure secret key if not set
SECRET_KEY="${SECRET_KEY:-$(openssl rand -base64 32)}"
cat > "/etc/systemd/system/$SVC_NAME" <<EOF
[Unit]
Description=YggSec Service
After=network.target

[Service]
User=$APP_USER
Group=$APP_GROUP
WorkingDirectory=$APP_DIR
Environment=SECRET_KEY=$SECRET_KEY
ExecStart=$VENV_DIR/bin/gunicorn -w 2 -b 127.0.0.1:5000 src.api.app:app
Restart=on-failure

# Create /run/wireguard at start (tmpfs) with safe perms
RuntimeDirectory=wireguard
RuntimeDirectoryMode=0755

# Least-privilege caps for wg/nft/ip
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

# Filesystem hardening
ProtectSystem=full
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
ReadWritePaths=$APP_DIR /etc/wireguard /etc/nftables.d $LOG_DIR /run/wireguard

PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK
RestrictNamespaces=true
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources

[Install]
WantedBy=multi-user.target
EOF

echo "[8/10] Nginx TLS reverse proxy"
mkdir -p /etc/nginx/ssl
if [ ! -s /etc/nginx/ssl/yggsec.key ] || [ ! -s /etc/nginx/ssl/yggsec.crt ]; then
  openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
    -keyout /etc/nginx/ssl/yggsec.key \
    -out  /etc/nginx/ssl/yggsec.crt \
    -subj "/C=US/ST=State/L=City/O=Organization/OU=YggSec/CN=yggsec/emailAddress=admin@example.com"
  chmod 600 /etc/nginx/ssl/yggsec.key
  chmod 644 /etc/nginx/ssl/yggsec.crt
fi

# Load management interface configuration
source /tmp/yggsec_mgmt_access.conf

# Generate nginx config based on management interface choice
if [ "$MGMT_IFACE" = "all" ]; then
    # Listen on all interfaces (original behavior)
    NGINX_LISTEN="listen 443 ssl default_server;"
else
    # Listen on specific interface only
    MGMT_IP=$(ip addr show "$MGMT_IFACE" 2>/dev/null | grep -E "inet [0-9]+\." | grep -v "127\." | head -1 | awk '{print $2}' | cut -d'/' -f1)
    if [ -n "$MGMT_IP" ]; then
        NGINX_LISTEN="listen ${MGMT_IP}:443 ssl;"
        echo "Management interface will be accessible on: https://${MGMT_IP}"
    else
        echo "Warning: Could not get IP for $MGMT_IFACE, falling back to all interfaces"
        NGINX_LISTEN="listen 443 ssl default_server;"
    fi
fi

tee /etc/nginx/sites-available/yggsec >/dev/null <<NGINX
server {
    $NGINX_LISTEN
    server_name your-domain.com yggsec _;
    ssl_certificate     /etc/nginx/ssl/yggsec.crt;
    ssl_certificate_key /etc/nginx/ssl/yggsec.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINX

ln -sf /etc/nginx/sites-available/yggsec /etc/nginx/sites-enabled/yggsec
rm -f /etc/nginx/sites-enabled/default
nginx -t && systemctl enable --now nginx && systemctl reload nginx || {
  echo "Nginx config failed. Check /var/log/nginx/error.log"; exit 1;
}

# Clean up temporary management config file
rm -f /tmp/yggsec_mgmt_access.conf

# (Optional) open firewall for 80/443 if host firewall is active
if command -v nft >/dev/null 2>&1; then
  nft add rule inet filter input tcp dport {80,443} accept 2>/dev/null || true
fi

echo "[8a/10] Configure Suricata IPS mode"
# Create systemd override directory for Suricata
install -d /etc/systemd/system/suricata.service.d

# Create IPS mode configuration (NFQUEUE - blocks threats)
tee /etc/systemd/system/suricata.service.d/override.conf >/dev/null <<'EOF'
[Service]
ExecStart=
ExecStart=/usr/bin/suricata -D -c /etc/suricata/suricata.yaml -q 0 --pidfile /run/suricata.pid
EOF

echo "[9/10] Enable basic app service"
systemctl daemon-reload
systemctl enable "$SVC_NAME"

# Configure Suricata but leave disabled by default (advanced feature)
systemctl daemon-reload
systemctl stop suricata || true
systemctl disable suricata || true
echo "Suricata IPS installed but disabled by default"
echo "To enable: sudo systemctl enable --now suricata"

echo "[10/10] Status"
systemctl --no-pager status "$SVC_NAME" || true
echo "Logs: journalctl -u $SVC_NAME -f"

# Determine web interface access URL for user guidance
MGMT_IP=$(ip addr show "$MGMT_IFACE" 2>/dev/null | grep -E "inet [0-9]+\." | grep -v "127\." | head -1 | awk '{print $2}' | cut -d'/' -f1)
if [ -n "$MGMT_IP" ]; then
    WEB_URL="https://${MGMT_IP}"
else
    # Fallback to primary IP if management interface detection fails
    FALLBACK_IP=$(ip route get 1.1.1.1 2>/dev/null | grep -oP 'src \K\S+' | head -1)
    WEB_URL="https://${FALLBACK_IP:-YOUR_SERVER_IP}"
fi

echo ""
echo "============================================================"
echo "[OK] YggSec installation completed successfully!"
echo "============================================================"
echo "Installation finished without interruption"
echo "Installation directory: $APP_DIR"
echo ""
echo "🌐 WEB INTERFACE ACCESS:"
echo "   URL: $WEB_URL"
echo "   Port: 443 (HTTPS)"
echo "   Status: Ready after application setup"
echo ""
echo "NEXT STEPS:"
echo "1. Complete YggSec application setup:"
echo "   sudo $VENV_DIR/bin/python $APP_DIR/scripts/yggsec_setup.py factory-reset-all --user administrator --app-user $APP_USER"
echo "   (You will be prompted securely for the admin password)"
echo "   (Shell history will be cleared automatically for security)"
echo ""
echo "3. Access web interface:"
echo "   Open: $WEB_URL"
echo "   Login with the credentials you set during setup"
echo ""
echo "MAINTENANCE COMMANDS:"
echo "  - Reset admin only: sudo $VENV_DIR/bin/python $APP_DIR/scripts/yggsec_setup.py factory-reset"
echo "  - View logs: journalctl -u yggsec -f"

