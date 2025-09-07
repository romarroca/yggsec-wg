#!/usr/bin/env python3
import os, json, time, ipaddress, subprocess, netifaces, re, tempfile
from json import JSONDecodeError
from typing import List, Dict
from src.utils.utils import run_priv, run_text, write_text_atomic, write_json_atomic

# ===== Paths / constants =====
ROOT_DIR = os.environ.get("YGGSEC_ROOT", "/opt/yggsec")
CFG_FILE = os.path.join(ROOT_DIR, "topology.json")
KEYS_DIR = os.path.join(ROOT_DIR, "keys")
WG_DIR = os.path.join(ROOT_DIR, "configs")

WG_IFACE = "wg0"
WG_PORT = 51820
HANDSHAKE_STALE_SECS = 180  # peer online if handshake seen within window


def _run_cmd(cmd, input_text=None):
    try:
        kw = dict(text=True, capture_output=True)
        if input_text is not None:
            kw["input"] = input_text
        cp = run_priv(cmd, **kw)
        return True, (cp.stdout or "").strip()
    except subprocess.CalledProcessError as e:
        msg = (e.stderr or e.stdout or "non-zero exit").strip()
        return False, msg[:400]
    except Exception as e:
        return False, f"System error: {e.__class__.__name__}"


# ===== FS helpers =====
def ensure_dirs():
    os.makedirs(ROOT_DIR, exist_ok=True)
    os.makedirs(KEYS_DIR, exist_ok=True)
    os.makedirs(WG_DIR, exist_ok=True)


def topology_present() -> bool:
    return os.path.isfile(CFG_FILE) and os.path.getsize(CFG_FILE) > 0


def load_topology():
    try:
        with open(CFG_FILE, "r") as f:
            data = json.load(f)
        return (
            data
            if isinstance(data, dict) and "hub" in data and "spokes" in data
            else None
        )
    except (FileNotFoundError, JSONDecodeError):
        return None


def save_topology(topology: dict):
    """Save topology atomically using secure temporary file."""
    write_json_atomic(CFG_FILE, topology, 0o600)


def wipe_state():
    try:
        if os.path.exists(CFG_FILE):
            os.remove(CFG_FILE)
    except Exception:
        pass
    for p in (KEYS_DIR, WG_DIR):
        if os.path.isdir(p):
            for root, dirs, files in os.walk(p, topdown=False):
                for name in files:
                    try:
                        os.remove(os.path.join(root, name))
                    except Exception:
                        pass
                for name in dirs:
                    try:
                        os.rmdir(os.path.join(root, name))
                    except Exception:
                        pass
            try:
                os.rmdir(p)
            except Exception:
                pass


# ===== Basics =====
def choose_interface_ip() -> str:
    """Choose interface IP with input validation."""
    bad = ("lo", "wg", "docker", "br-", "veth", "tailscale", "tun")
    for iface in netifaces.interfaces():
        # Validate interface name
        if not re.match(r"^[a-zA-Z0-9_.-]+$", iface) or iface.startswith(bad):
            continue
        try:
            addrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET in addrs:
                ip4 = addrs[netifaces.AF_INET][0].get("addr")
                if ip4 and not ip4.startswith("127."):
                    # Validate IP format
                    ipaddress.ip_address(ip4)
                    return ip4
        except (ValueError, KeyError):
            continue
    return "127.0.0.1"


def validate_key_prefix(prefix: str) -> bool:
    """Validate key prefix for safe file naming."""
    if not prefix or not isinstance(prefix, str):
        return False

    prefix = prefix.strip()
    if not prefix:
        return False

    # Only allow alphanumeric, dash, underscore (same as spoke names)
    if not re.match(r"^[a-zA-Z0-9_-]{1,30}$", prefix):
        return False

    # Enhanced path traversal prevention with normalization
    normalized_prefix = os.path.normpath(prefix)
    if (
        normalized_prefix != prefix
        or ".." in normalized_prefix
        or "/" in normalized_prefix
        or "\\" in normalized_prefix
        or os.path.isabs(normalized_prefix)
    ):
        return False

    return True


def gen_keypair(prefix: str):
    """Generate WireGuard keypair with secure file permissions."""
    if not validate_key_prefix(prefix):
        raise ValueError(
            "Invalid key prefix: only alphanumeric, dash, underscore allowed (max 30 chars)"
        )

    ensure_dirs()
    priv_path = os.path.join(KEYS_DIR, f"{prefix}_private.key")
    pub_path = os.path.join(KEYS_DIR, f"{prefix}_public.key")
    if not os.path.exists(priv_path):
        priv = run_text(["wg", "genkey"]).strip()
        pub = run_text(["wg", "pubkey"], input=priv + "\n").strip()
        # Use atomic writes with proper permissions
        write_text_atomic(priv_path, priv, 0o600)
        write_text_atomic(pub_path, pub, 0o644)
    else:
        with open(priv_path, "r") as f:
            priv = f.read().strip()
        with open(pub_path, "r") as f:
            pub = f.read().strip()
    return priv, pub


# ===== WireGuard config generation =====
def _hub_addr_from_subnet(cidr: str) -> str:
    """Generate hub IP address from subnet safely."""
    if not _valid_cidr(cidr):
        raise ValueError(f"Invalid subnet for hub: {cidr}")

    try:
        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        if not hosts:
            raise ValueError(f"Subnet {cidr} has no host addresses")
        return f"{hosts[0]}/{net.prefixlen}"  # first host
    except (ValueError, IndexError) as e:
        raise ValueError(f"Cannot generate hub address from {cidr}: {e}")


def generate_hub_conf(topology: dict, hub_priv: str) -> str:
    """Generate wg0.conf for the hub (route-safe)."""
    ensure_dirs()
    hub_addr = _hub_addr_from_subnet(topology["hub"]["subnet"])

    # Gather local IPv4 networks on this box to avoid duplicate routes
    local_nets = set()
    try:
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
            for a in addrs:
                ip = a.get("addr")
                mask = a.get("netmask")
                if ip and mask:
                    try:
                        n = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                        local_nets.add(str(n))
                    except Exception:
                        pass
    except Exception:
        pass

    cfg = f"""[Interface]
Address = {hub_addr}
PrivateKey = {hub_priv}
ListenPort = {WG_PORT}
# Pure nftables; forwarding only.
PostUp   = sysctl -w net.ipv4.ip_forward=1
PostDown = :
"""

    for s in topology["spokes"]:
        vpn_ip = (s.get("vpn_ip") or "").strip()
        lan = (s.get("lan_subnet") or "").strip()
        parts = [vpn_ip] if vpn_ip else []
        if lan and lan not in local_nets:
            parts.append(lan)

        cfg += f"""

[Peer]
PublicKey  = {s['public_key']}
AllowedIPs = {", ".join(parts)}
"""

    path = os.path.join(WG_DIR, f"{WG_IFACE}.conf")
    with open(path, "w") as f:
        f.write(cfg)
    try:
        os.chmod(path, 0o600)  # silence 'world accessible' warning
    except Exception:
        pass
    return path


def generate_spoke_conf(name: str, spoke: dict, topology: dict) -> str:
    ensure_dirs()
    hub_pub = topology["hub"]["public_key"]
    hub_ip = topology["hub"]["public_ip"]
    hub_lans = topology["hub"].get("lan_subnets", []) or []

    if topology.get("mode", "hub-only") == "sdwan":
        allowed = [topology["hub"]["subnet"]] + hub_lans
    else:
        # Use full VPN subnet for mesh connectivity, not just hub IP
        allowed = [topology["hub"]["subnet"]] + hub_lans

    priv = open(os.path.join(KEYS_DIR, f"{name}_private.key")).read().strip()
    cfg = f"""[Interface]
Address    = {spoke['vpn_ip']}
PrivateKey = {priv}

[Peer]
PublicKey  = {hub_pub}
Endpoint   = {hub_ip}:{WG_PORT}
AllowedIPs = {", ".join(allowed)}
PersistentKeepalive = 25
"""
    p = os.path.join(WG_DIR, f"{name}-{WG_IFACE}.conf")
    with open(p, "w") as f:
        f.write(cfg)
    try:
        os.chmod(p, 0o644)  # readable for QR
    except Exception:
        pass
    return p


# ===== FULL restart (down -> up) =====
def validate_wg_interface(iface: str) -> bool:
    """Validate WireGuard interface name."""
    if not iface or not isinstance(iface, str):
        return False

    # Only allow wg followed by digits
    return bool(re.match(r"^wg[0-9]{1,2}$", iface))


def restart_full(wg_conf_path: str):
    if not validate_wg_interface(WG_IFACE):
        return False, f"Invalid iface: {WG_IFACE}"

    unit = f"wg-up@{WG_IFACE}"

    ok, msg = _run_cmd(["systemctl", "--no-pager", "--plain", "try-restart", unit])
    if ok:
        return True, "restarted"

    _run_cmd(["systemctl", "--no-pager", "--plain", "daemon-reload"])
    ok2, msg2 = _run_cmd(["systemctl", "--no-pager", "--plain", "restart", unit])
    return (True, "restarted") if ok2 else (False, f"restart failed: {msg2}")


# ===== High-level ops =====
def regenerate_all():
    topo = load_topology()
    if not topo:
        return
    hub_priv, hub_pub = gen_keypair("hub")
    topo["hub"]["public_key"] = hub_pub
    save_topology(topo)
    wg_path = generate_hub_conf(topo, hub_priv)
    for s in topo.get("spokes", []):
        generate_spoke_conf(s["name"], s, topo)
    restart_full(wg_path)


def regenerate_configs_only():
    """Generate WireGuard configs without restarting service (for init/factory-reset)"""
    topo = load_topology()
    if not topo:
        return
    # Don't regenerate hub keys during init - use existing ones
    hub_priv_path = os.path.join(KEYS_DIR, "hub_private.key")
    if os.path.exists(hub_priv_path):
        with open(hub_priv_path, "r") as f:
            hub_priv = f.read().strip()
    else:
        # Fallback if key doesn't exist
        hub_priv, hub_pub = gen_keypair("hub")
        topo["hub"]["public_key"] = hub_pub
        save_topology(topo)

    wg_path = generate_hub_conf(topo, hub_priv)
    for s in topo.get("spokes", []):
        generate_spoke_conf(s["name"], s, topo)
    return wg_path


def init_topology():
    """Interactive topology initialization (prompts for everything)"""
    ensure_dirs()

    # Get and validate VPN subnet
    subnet_input = (
        input("Enter VPN subnet [default 10.250.250.0/24]: ") or "10.250.250.0/24"
    )
    subnet = subnet_input.strip()
    if not _valid_cidr(subnet):
        raise ValueError(f"Invalid VPN subnet: {subnet}")

    # Get and validate hub LAN subnets
    lans_input = (
        input("Enter hub LAN subnets (comma-separated, leave empty if none): ") or ""
    )
    hub_lans = []
    if lans_input.strip():
        for lan in lans_input.split(","):
            lan = lan.strip()
            if lan:  # Skip empty entries
                if not _valid_cidr(lan):
                    raise ValueError(f"Invalid hub LAN subnet: {lan}")
                hub_lans.append(lan)

    mode = "hub-only" if hub_lans else "sdwan"

    hub_priv, hub_pub = gen_keypair("hub")
    public_ip = choose_interface_ip()
    topo = {
        "mode": mode,
        "hub": {
            "public_ip": public_ip,
            "interface": "auto-detected",  # For legacy interactive mode
            "subnet": subnet,
            "lan_subnets": hub_lans,
            "public_key": hub_pub,
        },
        "spokes": [],
    }
    save_topology(topo)
    regenerate_all()


def init_topology_with_interface(public_ip: str, interface: str = "auto-detected"):
    """Initialize topology with preserved interface info (non-interactive for factory reset)"""
    ensure_dirs()

    # Use defaults for factory reset - user can modify via web UI later
    subnet = "10.250.250.0/24"
    hub_lans = []  # Start with no LANs - user can add via web UI
    mode = "hub-only"  # Default to hub-only mode

    hub_priv, hub_pub = gen_keypair("hub")
    topo = {
        "mode": mode,
        "hub": {
            "public_ip": public_ip,
            "interface": interface,
            "subnet": subnet,
            "lan_subnets": hub_lans,
            "public_key": hub_pub,
        },
        "spokes": [],
    }
    save_topology(topo)
    # Generate configs without restarting WireGuard during factory reset
    regenerate_configs_only()


def _valid_cidr(c: str) -> bool:
    """Validate CIDR notation with enhanced checks."""
    if not c or not isinstance(c, str):
        return False

    c = c.strip()
    if not c:
        return False

    try:
        network = ipaddress.ip_network(c, strict=False)
        # Only allow reasonable IPv4 networks
        if network.version != 4:
            return False
        # Reasonable prefix lengths for LANs
        if network.prefixlen < 8 or network.prefixlen > 30:
            return False
        return True
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError):
        return False


def restart_service():
    try:
        run_priv(
            ["systemctl", "daemon-reload"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        run_priv(["systemctl", "restart", "yggsec"], text=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        detail = ""
        if e.stderr:
            detail = (
                e.stderr.decode(errors="ignore")
                if isinstance(e.stderr, (bytes, bytearray))
                else str(e.stderr)
            )
        raise RuntimeError(f"Service restart failed: {detail}")


# ===== Spokes / Hub LAN mgmt =====
def validate_spoke_name(name: str) -> bool:
    """Validate spoke name for security."""
    return bool(re.match(r"^[a-zA-Z0-9_-]{1,20}$", name))


def add_spoke(name: str, lan_subnet: str | None = None):
    topo = load_topology()
    if topo is None:
        return
    if not name or not validate_spoke_name(name):
        raise ValueError(
            "Invalid spoke name: only alphanumeric, dash, underscore allowed (max 20 chars)"
        )

    lan_subnet = (lan_subnet or "").strip()
    if lan_subnet and not _valid_cidr(lan_subnet):
        raise ValueError(f"Invalid LAN subnet: {lan_subnet}")

    # Generate VPN IP safely
    try:
        net = ipaddress.ip_network(topo["hub"]["subnet"], strict=False)
        hosts = list(net.hosts())
        spoke_idx = len(topo["spokes"]) + 1
        if spoke_idx >= len(hosts):
            raise ValueError("VPN subnet is full - cannot add more spokes")
        host = hosts[spoke_idx]
        vpn_ip = f"{host}/32"
    except (ValueError, IndexError) as e:
        raise ValueError(f"Cannot assign VPN IP: {e}")

    _, pub = gen_keypair(name)
    s = {
        "name": name.strip(),
        "lan_subnet": lan_subnet,
        "vpn_ip": vpn_ip,
        "public_key": pub,
    }
    topo["spokes"].append(s)
    save_topology(topo)

    generate_spoke_conf(name, s, topo)
    restart_full(os.path.join(WG_DIR, f"{WG_IFACE}.conf"))


def add_hub_lan(lans_input: str = None):
    topo = load_topology()
    if topo is None:
        return
    if not lans_input:
        lans_input = input("Enter additional hub LAN subnets (comma-separated): ")

    # Validate each subnet
    new_lans = []
    for subnet in lans_input.split(","):
        subnet = subnet.strip()
        if not subnet:
            continue
        if not _valid_cidr(subnet):
            raise ValueError(f"Invalid LAN subnet: {subnet}")
        new_lans.append(subnet)

    if not new_lans:
        raise ValueError("No valid LAN subnets provided")

    topo["hub"]["lan_subnets"].extend(new_lans)
    topo["hub"]["lan_subnets"] = sorted(set(topo["hub"]["lan_subnets"]))
    save_topology(topo)
    regenerate_all()


def delete_spoke(name: str) -> bool:
    topo = load_topology()
    if topo is None:
        return False
    before = len(topo["spokes"])
    topo["spokes"] = [s for s in topo["spokes"] if s["name"] != name]
    save_topology(topo)
    for p in (
        os.path.join(KEYS_DIR, f"{name}_private.key"),
        os.path.join(KEYS_DIR, f"{name}_public.key"),
        os.path.join(WG_DIR, f"{name}-{WG_IFACE}.conf"),
    ):
        if os.path.exists(p):
            try:
                os.remove(p)
            except Exception:
                pass
    changed = len(topo["spokes"]) != before
    if changed:
        restart_full(os.path.join(WG_DIR, f"{WG_IFACE}.conf"))
    return changed


def regenerate_hub_keys() -> bool:
    topo = load_topology()
    if topo is None:
        return False
    _, pub = gen_keypair("hub-new")
    os.replace(
        os.path.join(KEYS_DIR, "hub-new_private.key"),
        os.path.join(KEYS_DIR, "hub_private.key"),
    )
    os.replace(
        os.path.join(KEYS_DIR, "hub-new_public.key"),
        os.path.join(KEYS_DIR, "hub_public.key"),
    )
    topo["hub"]["public_key"] = pub
    save_topology(topo)
    regenerate_all()
    return True


def regenerate_spoke_keys(name: str) -> bool:
    topo = load_topology()
    if topo is None:
        return False
    sp = next((s for s in topo["spokes"] if s["name"] == name), None)
    if not sp:
        return False
    _, pub = gen_keypair(f"{name}-new")
    os.replace(
        os.path.join(KEYS_DIR, f"{name}-new_private.key"),
        os.path.join(KEYS_DIR, f"{name}_private.key"),
    )
    os.replace(
        os.path.join(KEYS_DIR, f"{name}-new_public.key"),
        os.path.join(KEYS_DIR, f"{name}_public.key"),
    )
    sp["public_key"] = pub
    save_topology(topo)
    regenerate_all()
    return True


def remove_hub_lan(lan_subnet: str):
    """Remove a specific LAN subnet from hub configuration."""
    topo = load_topology()
    if topo is None:
        raise ValueError("No topology configuration found")

    if not _valid_cidr(lan_subnet):
        raise ValueError(f"Invalid LAN subnet: {lan_subnet}")

    if lan_subnet not in topo["hub"]["lan_subnets"]:
        raise ValueError(f"LAN subnet {lan_subnet} not found in hub configuration")

    topo["hub"]["lan_subnets"].remove(lan_subnet)
    save_topology(topo)
    regenerate_all()


def edit_vpn_subnet(vpn_subnet: str):
    """Edit the VPN subnet for the hub. This will require all clients to be reconfigured."""
    topo = load_topology()
    if topo is None:
        raise ValueError("No topology configuration found")

    if not _valid_cidr(vpn_subnet):
        raise ValueError(f"Invalid VPN subnet: {vpn_subnet}")

    # Parse the subnet to get network and prefix
    try:
        import ipaddress

        network = ipaddress.IPv4Network(vpn_subnet, strict=False)
        if network.prefixlen < 16 or network.prefixlen > 30:
            raise ValueError("VPN subnet prefix must be between /16 and /30")
    except ValueError as e:
        raise ValueError(f"Invalid subnet format: {e}")

    # Update topology
    old_subnet = topo["hub"]["subnet"]
    topo["hub"]["subnet"] = str(network)

    # Update hub IP (first usable IP in subnet)
    hub_ip = str(list(network.hosts())[0])

    # Reassign spoke VPN IPs to new subnet
    host_iter = iter(network.hosts())
    next(host_iter)  # Skip hub IP

    for i, spoke in enumerate(topo["spokes"]):
        try:
            spoke["vpn_ip"] = str(next(host_iter))
        except StopIteration:
            raise ValueError(
                f"New subnet {vpn_subnet} is too small for {len(topo['spokes'])} spokes"
            )

    save_topology(topo)
    regenerate_all()

    return f"VPN subnet changed from {old_subnet} to {vpn_subnet}. All clients must be reconfigured."
