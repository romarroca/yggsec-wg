"""
Legacy core.py compatibility layer
This file provides the exact same interface as the original core.py
but uses the new service architecture underneath

To use the new architecture, import from src.services directly
To maintain compatibility, import from this file
"""

# Import everything from the legacy adapter
from src.integration.legacy_adapter import *

# Import the remaining functions that weren't covered yet
import os
import ipaddress
import subprocess
import netifaces
import re

from src.config.settings import get_config
from src.services.wireguard_service import WireGuardService
from src.core.validators import NetworkValidator, WireGuardValidator


def choose_interface_ip():
    """Choose interface IP with input validation."""
    bad = ("lo", "wg", "docker", "br-", "veth", "tailscale", "tun")
    for iface in netifaces.interfaces():
        # Validate interface name
        if not re.match(r'^[a-zA-Z0-9_.-]+$', iface) or iface.startswith(bad):
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


def _valid_cidr(c):
    """Legacy CIDR validation - maintains original interface"""
    try:
        NetworkValidator.validate_cidr(c)
        return True
    except:
        return False


def validate_spoke_name(name):
    """Legacy spoke name validation - maintains original interface"""
    try:
        WireGuardValidator.validate_spoke_name(name)
        return True
    except:
        return False


def regenerate_all():
    """Regenerate all configurations - legacy interface"""
    config = get_config()
    wg_service = WireGuardService(config)
    
    topo = wg_service.load_topology()
    if not topo:
        return
    
    hub_priv, hub_pub = wg_service.generate_keypair("hub")
    topo["hub"]["public_key"] = hub_pub
    wg_service.save_topology(topo)
    
    wg_path = wg_service.generate_hub_config(topo, hub_priv)
    for spoke in topo.get("spokes", []):
        wg_service.generate_spoke_config(spoke["name"], spoke, topo)
    
    wg_service.restart_interface(wg_path)


def regenerate_configs_only():
    """Generate WireGuard configs without restarting service"""
    config = get_config()
    wg_service = WireGuardService(config)
    
    topo = wg_service.load_topology()
    if not topo:
        return
    
    # Don't regenerate hub keys during init - use existing ones
    hub_priv_path = os.path.join(config.keys_dir, "hub_private.key")
    if os.path.exists(hub_priv_path):
        with open(hub_priv_path, 'r') as f:
            hub_priv = f.read().strip()
    else:
        # Fallback if key doesn't exist
        hub_priv, hub_pub = wg_service.generate_keypair("hub")
        topo["hub"]["public_key"] = hub_pub
        wg_service.save_topology(topo)
    
    wg_path = wg_service.generate_hub_config(topo, hub_priv)
    for spoke in topo.get("spokes", []):
        wg_service.generate_spoke_config(spoke["name"], spoke, topo)
    return wg_path


def restart_service():
    """Restart YggSec service - legacy interface"""
    try:
        from src.utils.utils import run_priv
        run_priv(["systemctl", "daemon-reload"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run_priv(["systemctl", "restart", "yggsec"], text=True, capture_output=True)
        return True
    except subprocess.CalledProcessError as e:
        detail = ""
        if e.stderr:
            detail = e.stderr.decode(errors="ignore") if isinstance(e.stderr, (bytes, bytearray)) else str(e.stderr)
        raise RuntimeError(f"Service restart failed: {detail}")


def add_spoke(name, lan_subnet=None):
    """Add spoke - legacy interface with error handling"""
    config = get_config()
    wg_service = WireGuardService(config)
    
    topo = wg_service.load_topology()
    if topo is None:
        return
    
    # Validation
    if not validate_spoke_name(name):
        raise ValueError("Invalid spoke name: only alphanumeric, dash, underscore allowed (max 20 chars)")
    
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
    
    _, pub = wg_service.generate_keypair(name)
    spoke_data = {
        "name": name.strip(),
        "lan_subnet": lan_subnet,
        "vpn_ip": vpn_ip,
        "public_key": pub,
    }
    topo["spokes"].append(spoke_data)
    wg_service.save_topology(topo)
    
    wg_service.generate_spoke_config(name, spoke_data, topo)
    restart_full(os.path.join(config.wg_dir, f"{config.WG_IFACE}.conf"))


def delete_spoke(name):
    """Delete spoke - legacy interface"""
    config = get_config()
    wg_service = WireGuardService(config)
    
    topo = wg_service.load_topology()
    if topo is None:
        return False
    
    before = len(topo["spokes"])
    topo["spokes"] = [s for s in topo["spokes"] if s["name"] != name]
    wg_service.save_topology(topo)
    
    # Clean up files
    for path in (
        os.path.join(config.keys_dir, f"{name}_private.key"),
        os.path.join(config.keys_dir, f"{name}_public.key"),
        os.path.join(config.wg_dir, f"{name}-{config.WG_IFACE}.conf"),
    ):
        if os.path.exists(path):
            try:
                os.remove(path)
            except Exception:
                pass
    
    changed = len(topo["spokes"]) != before
    if changed:
        restart_full(os.path.join(config.wg_dir, f"{config.WG_IFACE}.conf"))
    return changed


# Add the remaining functions that app.py might use
def regenerate_hub_keys():
    """Regenerate hub keys - legacy interface"""
    config = get_config()
    wg_service = WireGuardService(config)
    
    topo = wg_service.load_topology()
    if topo is None:
        return False
    
    try:
        _, pub = wg_service.generate_keypair("hub-new")
        os.replace(os.path.join(config.keys_dir, "hub-new_private.key"), 
                  os.path.join(config.keys_dir, "hub_private.key"))
        os.replace(os.path.join(config.keys_dir, "hub-new_public.key"),  
                  os.path.join(config.keys_dir, "hub_public.key"))
        topo["hub"]["public_key"] = pub
        wg_service.save_topology(topo)
        regenerate_all()
        return True
    except Exception:
        return False


def regenerate_spoke_keys(name):
    """Regenerate spoke keys - legacy interface"""
    config = get_config()
    wg_service = WireGuardService(config)
    
    topo = wg_service.load_topology()
    if topo is None:
        return False
    
    spoke = next((s for s in topo["spokes"] if s["name"] == name), None)
    if not spoke:
        return False
    
    try:
        _, pub = wg_service.generate_keypair(f"{name}-new")
        os.replace(os.path.join(config.keys_dir, f"{name}-new_private.key"), 
                  os.path.join(config.keys_dir, f"{name}_private.key"))
        os.replace(os.path.join(config.keys_dir, f"{name}-new_public.key"),  
                  os.path.join(config.keys_dir, f"{name}_public.key"))
        spoke["public_key"] = pub
        wg_service.save_topology(topo)
        regenerate_all()
        return True
    except Exception:
        return False