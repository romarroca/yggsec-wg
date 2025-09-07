#!/usr/bin/env python3
# yggsec_setup.py
import os
import sys
import json
import secrets
import shutil
import subprocess
from pathlib import Path
from argparse import ArgumentParser
from werkzeug.security import generate_password_hash

import netifaces

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.core import core  # uses utils.run_priv internally

APP_DIR = Path(__file__).resolve().parent.parent
VENV_DIR = APP_DIR / "venv"
GUNICORN = VENV_DIR / "bin" / "gunicorn"
UNIT_PATH = Path("/etc/systemd/system/yggsec.service")
LOG_DIR = Path("/var/log/yggsec")
CONFIG_DIR = APP_DIR / "configs"
KEYS_DIR = APP_DIR / "keys"
ADMINS_FILE = CONFIG_DIR / "admins.json"


def _require_root():
    if os.geteuid() != 0:
        print("must run as root", file=sys.stderr)
        sys.exit(1)


def _chown(path: Path, user: str):
    try:
        subprocess.run(["chown", "-R", f"{user}:{user}", str(path)], check=True, shell=False)
    except subprocess.CalledProcessError as e:
        print(f"Warning: Failed to chown {path} to {user}: {e}")
    except Exception as e:
        print(f"Warning: Unexpected error changing ownership of {path}: {e}")


def _chmod(path: Path, mode: int):
    try:
        os.chmod(path, mode)
        print(f"Changed permissions of {path} to {oct(mode)}")
    except Exception as e:
        print(f"Warning: Failed to chmod {path} to {oct(mode)}: {e}")


def ensure_app_permissions(app_user: str):
    """Make sure app dirs/files are owned by APP_USER with sane perms."""
    APP_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    _chown(APP_DIR, app_user)
    _chown(LOG_DIR, app_user)
    _chown(CONFIG_DIR, app_user)
    _chown(KEYS_DIR, app_user)

    _chmod(APP_DIR, 0o755)  # App dir needs to be readable
    _chmod(CONFIG_DIR, 0o750)
    _chmod(KEYS_DIR, 0o700)
    if ADMINS_FILE.exists():
        _chmod(ADMINS_FILE, 0o640)

    # Fix topology.json ownership if it exists (created by core.py as root)
    topology_file = APP_DIR / "topology.json"
    if topology_file.exists():
        _chown(topology_file, app_user)
        _chmod(topology_file, 0o644)


def write_admin(username: str, password: str | None, app_user: str):
    """Create configs/admins.json with a single admin. Returns the plaintext if generated."""
    user = (username or "administrator").strip()
    plain = password or secrets.token_urlsafe(32)
    data = {
        "admins": [{
            "username": user,
            "first_name": "Admin",
            "last_name": "User",
            "password_hash": generate_password_hash(plain),
            "must_change": True,
        }]
    }
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ADMINS_FILE.write_text(json.dumps(data, indent=2))

    # perms/ownership so gunicorn (running as APP_USER) can read
    _chmod(ADMINS_FILE, 0o640)
    _chown(ADMINS_FILE, app_user)
    return None if password else plain


def get_network_interfaces():
    """Get available network interfaces excluding loopback and WireGuard."""
    interfaces = []
    for iface in netifaces.interfaces():
        if iface == "lo" or iface.startswith("wg"):
            continue
        try:
            addrs = netifaces.ifaddresses(iface)
            ipv4_addrs = addrs.get(netifaces.AF_INET, [])
            ip = ipv4_addrs[0]['addr'] if ipv4_addrs else "no IP"
            interfaces.append((iface, ip))
        except (KeyError, IndexError):
            interfaces.append((iface, "no IP"))
    return interfaces


def initialize_topology_interactive(app_user: str):
    """Interactive topology initialization with interface detection."""
    interfaces = get_network_interfaces()
    if not interfaces:
        print("No network interfaces found. Abort.")
        sys.exit(1)

    print("Found interfaces:")
    for i, (iface, ip) in enumerate(interfaces):
        print(f"  [{i}] {iface} ({ip})")

    # Pick OUTSIDE/WAN interface
    while True:
        try:
            idx = int(input("Select OUTSIDE interface index: "))
            if 0 <= idx < len(interfaces):
                break
            print("Invalid index.")
        except ValueError:
            print("Invalid input.")
        except KeyboardInterrupt:
            print("\nSetup cancelled by user.")
            sys.exit(1)

    net_iface, selected_ip = interfaces[idx]
    print(f"Selected OUTSIDE: {net_iface}")

    # Handle case where interface has no IP yet
    if selected_ip == "no IP":
        try:
            selected_ip = input(f"Interface {net_iface} has no IP. Enter expected public IP: ").strip()
            if not selected_ip:
                selected_ip = "127.0.0.1"
        except KeyboardInterrupt:
            print("\nSetup cancelled by user.")
            sys.exit(1)

    # Optional LAN interface
    lan_subnets = []
    try:
        cfg_lan = input("Configure a LAN interface too? [y/N]: ").strip().lower()
    except KeyboardInterrupt:
        print("\nSetup cancelled by user.")
        sys.exit(1)
    if cfg_lan.startswith('y'):
        while True:
            try:
                lidx = int(input(f"Select LAN interface index (not {net_iface}): "))
                if 0 <= lidx < len(interfaces) and interfaces[lidx][0] != net_iface:
                    break
                print("Invalid index.")
            except ValueError:
                print("Invalid input.")
            except KeyboardInterrupt:
                print("\nSetup cancelled by user.")
                sys.exit(1)

        lan_iface = interfaces[lidx][0]
        print(f"Selected LAN: {lan_iface}")
        lan_subnets = ["192.168.50.0/24"]

    # Create topology with detected interface
    try:
        hub_priv, hub_pub = core.gen_keypair('hub')
        topo = {
            'mode': 'hub-only',
            'hub': {
                'public_ip': selected_ip,
                'interface': net_iface,
                'subnet': '10.250.250.0/24',
                'lan_subnets': lan_subnets,
                'public_key': hub_pub
            },
            'spokes': []
        }
        core.save_topology(topo)
        print("Topology initialized: hub-only mode")
        print(f"WAN Interface: {net_iface} ({selected_ip})")
        if lan_subnets:
            print(f"LAN subnets: {lan_subnets}")

        # Generate initial WireGuard config
        hub_wg_path = core.generate_hub_conf(topo, hub_priv)
        print(f"WireGuard hub configuration generated: {hub_wg_path}")

    except Exception as e:
        print(f"Error initializing topology: {e}")
        sys.exit(1)


def ensure_vpnfw(policy: str = "drop"):
    """
    Guarantee inet:vpnfw/forward exists with default DROP and is persisted.
    Idempotent. Works even if firewall.py is not importable.
    """
    # nft binary
    nft = shutil.which("nft")
    if not nft:
        raise SystemExit("nftables not installed (apt-get install -y nftables)")

    # Ensure persistence include
    os.makedirs("/etc/nftables.d", exist_ok=True)
    main_conf = "/etc/nftables.conf"
    include_line = 'include "/etc/nftables.d/*.nft"'
    if not os.path.exists(main_conf):
        Path(main_conf).write_text("#!/usr/sbin/nft -f\nflush ruleset\n" + include_line + "\n")
    else:
        data = Path(main_conf).read_text()
        if include_line not in data:
            Path(main_conf).write_text(data.rstrip() + "\n" + include_line + "\n")

    # Try to use firewall.py if available
    try:
        import firewall
        firewall.reset_firewall(policy)
    except Exception:
        # Fallback: create table/chain + baseline directly
        subprocess.run([nft, "delete", "table", "inet", "vpnfw"],
                       check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, shell=False)
        subprocess.run([nft, "add", "table", "inet", "vpnfw"], check=True, shell=False)
        subprocess.run([
            nft, "add", "chain", "inet", "vpnfw", "forward",
            "{", "type", "filter", "hook", "forward", "priority", "0", ";",
            "policy", policy, ";", "}"
        ], check=True, shell=False)
        if policy == "drop":
            subprocess.run([
                nft, "add", "rule", "inet", "vpnfw", "forward",
                "ct", "state", "established,related", "accept"
            ], check=True, shell=False)
            subprocess.run([nft, "add", "rule", "inet", "vpnfw", "forward",
                            "ct", "state", "invalid", "drop"], check=True, shell=False)

    # Persist current ruleset to /etc/nftables.d/vpnfw.nft
    out = subprocess.run([nft, "-s", "list", "table", "inet", "vpnfw"],
                         check=True, capture_output=True, text=True, shell=False).stdout
    Path("/etc/nftables.d/vpnfw.nft").write_text(out)

    # Load from main and enable service (if systemd exists)
    try:
        subprocess.run([nft, "-f", main_conf], check=True, shell=False)
        subprocess.run(["systemctl", "enable", "--now", "nftables"], check=False, shell=False)
    except Exception:
        pass


def install_service(app_user: str):
    """Install and start the systemd unit for YggSec."""
    ensure_app_permissions(app_user)

    secret = os.environ.get("SECRET_KEY", secrets.token_urlsafe(32))

    unit = f"""[Unit]
Description=YggSec Service
After=network.target

[Service]
User={app_user}
Group={app_user}
WorkingDirectory={APP_DIR}
Environment=SECRET_KEY={secret}
ExecStart={GUNICORN} -w 2 -b 127.0.0.1:5000 src.api.app:app
Restart=on-failure

# Create /run/wireguard at start (tmpfs) with safe perms
RuntimeDirectory=wireguard
RuntimeDirectoryMode=0755

# Least-privilege caps for wg/nft/ip
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=true

# Filesystem hardening (allow app + required system paths)
ProtectSystem=full
ProtectHome=true
ReadWritePaths={APP_DIR} /etc/wireguard /etc/nftables.d {LOG_DIR} /run/wireguard

PrivateTmp=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK

[Install]
WantedBy=multi-user.target
"""
    UNIT_PATH.write_text(unit)
    _chmod(UNIT_PATH, 0o644)

    subprocess.run(["systemctl", "daemon-reload"], check=True, shell=False)
    subprocess.run(["systemctl", "enable", "yggsec"], check=True, shell=False)
    subprocess.run(["systemctl", "restart", "yggsec"], check=True, shell=False)


def cmd_factory_reset_all(app_user: str, username: str, password: str | None):
    """Wipe state, rebuild topology, reset admin, install service, regenerate, restart WireGuard."""
    print("DANGER: wipes configs/keys/topology, regenerates, restarts service and WireGuard.")
    try:
        response = input('Type EXACTLY "RESET ALL" to continue: ').strip()
        if response != "RESET ALL":
            print("aborted")
            sys.exit(2)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)

    # 0) ensure perms upfront so following steps can write/read
    ensure_app_permissions(app_user)

    # 0.5) run permissions bootstrap (critical for WireGuard capabilities)
    print("[factory-reset] running permissions bootstrap")
    permission_script = APP_DIR / "scripts" / "permission.sh"
    if permission_script.exists():
        env = {"APP_DIR": str(APP_DIR), "APP_USER": app_user, "WG_IFACE": "wg0"}
        subprocess.run([str(permission_script)], env=env, check=True, shell=False)
    else:
        print(f"Warning: {permission_script} not found, skipping permissions bootstrap")

    # 1) preserve interface info before wiping state
    old_topology = core.load_topology()
    preserved_public_ip = None
    preserved_interface = None
    if old_topology and "hub" in old_topology:
        preserved_public_ip = old_topology["hub"].get("public_ip")
        preserved_interface = old_topology["hub"].get("interface", "auto-detected")
        print(f"[factory-reset] preserving interface: {preserved_interface} ({preserved_public_ip})")

    # 2) wipe app state (configs/keys/topology.json)
    core.wipe_state()

    # 3) interactive topology initialization with interface detection
    if preserved_public_ip:
        print(f"[factory-reset] using preserved interface: {preserved_interface} ({preserved_public_ip})")
        core.init_topology_with_interface(preserved_public_ip, preserved_interface)
    else:
        print("[factory-reset] detecting network interfaces")
        initialize_topology_interactive(app_user)

    # 2.5) fix topology.json ownership (created by core.py as root)
    ensure_app_permissions(app_user)

    # 3) recreate admin
    temp_pw = write_admin(username, password, app_user)
    print(f"[factory-reset] admin: {username or 'administrator'}")
    if password:
        print("[factory-reset] password supplied via env/arg")
    else:
        print(f"[factory-reset] temporary password (shown once): {temp_pw}")

    # 3.5) initialize nftables baseline (inet:vpnfw, default DROP)
    print("[factory-reset] initializing nftables baseline (inet:vpnfw, DROP)")
    ensure_vpnfw("drop")

    # 4) service install or repair
    install_service(app_user)

    # 5) regenerate configs and restart WireGuard cleanly
    wg_conf = core.regenerate_configs_only()
    if wg_conf:
        try:
            core.restart_full(wg_conf)
            print("[factory-reset] WireGuard service restarted successfully")
        except Exception as e:
            print(f"[factory-reset] Warning: WireGuard restart failed: {e}")
            print("[factory-reset] Configs generated successfully, manual restart may be needed")

    # 6) final permission fix after config generation
    ensure_app_permissions(app_user)
    print("[factory-reset] complete")


def cmd_factory_reset(username: str, password: str | None, app_user: str):
    """Overwrite admins.json only."""
    print("WARNING: this overwrites configs/admins.json")
    try:
        response = input('Type EXACTLY "RESET ALL": ').strip()
        if response != "RESET ALL":
            print("aborted")
            sys.exit(2)
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    ensure_app_permissions(app_user)
    temp = write_admin(username, password, app_user)
    print(f"[factory-reset] admin: {username or 'administrator'}")
    if password:
        print("[factory-reset] password supplied via env/arg")
    else:
        print(f"[factory-reset] temporary password (shown once): {temp}")
    # Nudge the app in case it was already running and needs to reload admins.json
    subprocess.run(["systemctl", "restart", "yggsec"], check=False, shell=False)


def main():
    _require_root()

    p = ArgumentParser(description="YggSec setup helper")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser(
        "factory-reset-all",
        help="wipe everything, recreate admin, install+start service, regenerate, restart",
    )
    a.add_argument("--user", default=os.environ.get("ADMIN_USERNAME", "administrator"))
    a.add_argument("--password", default=os.environ.get("ADMIN_PASSWORD"))
    a.add_argument("--app-user", default=os.environ.get("APP_USER") or os.environ.get("SUDO_USER") or "yggsec")

    b = sub.add_parser("factory-reset", help="overwrite admins.json only")
    b.add_argument("--user", default=os.environ.get("ADMIN_USERNAME", "administrator"))
    b.add_argument("--password", default=os.environ.get("ADMIN_PASSWORD"))
    b.add_argument("--app-user", default=os.environ.get("APP_USER") or os.environ.get("SUDO_USER") or "yggsec")

    c = sub.add_parser("install-service", help="install+enable systemd unit")
    c.add_argument("--app-user", default=os.environ.get("APP_USER") or os.environ.get("SUDO_USER") or "yggsec")

    args = p.parse_args()

    if args.cmd == "factory-reset-all":
        cmd_factory_reset_all(args.app_user, args.user, args.password)
    elif args.cmd == "factory-reset":
        cmd_factory_reset(args.user, args.password, args.app_user)
    elif args.cmd == "install-service":
        install_service(args.app_user)


if __name__ == "__main__":
    main()
