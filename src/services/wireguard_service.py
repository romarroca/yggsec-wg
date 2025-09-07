"""
WireGuard service following SOLID principles and dependency injection
Extracted from core.py with improved error handling and modularity
"""

import ipaddress
import json
import os
import subprocess
from typing import Dict, Optional, Tuple

from ..config.settings import BaseConfig
from ..core.exceptions import NetworkConfigError, WireGuardError
from ..core.validators import NetworkValidator, WireGuardValidator
from ..utils.utils import run_priv, run_text, write_json_atomic, write_text_atomic


class WireGuardService:
    """
    WireGuard management service with dependency injection
    Handles topology, peer management, and configuration generation
    """

    def __init__(self, config: BaseConfig):
        """
        Initialize WireGuard service with configuration

        Args:
            config: Configuration object
        """
        self.config = config
        self._ensure_directories()

    def _ensure_directories(self) -> None:
        """Ensure required directories exist with proper permissions"""
        for directory in [
            self.config.ROOT_DIR,
            self.config.keys_dir,
            self.config.wg_dir,
        ]:
            os.makedirs(directory, exist_ok=True)

    def topology_exists(self) -> bool:
        """Check if topology configuration exists and is not empty"""
        return (
            os.path.isfile(self.config.cfg_file)
            and os.path.getsize(self.config.cfg_file) > 0
        )

    def load_topology(self) -> Optional[Dict]:
        """
        Load topology configuration from file

        Returns:
            Dict: Topology data or None if not found/invalid

        Raises:
            NetworkConfigError: If topology file is corrupted
        """
        try:
            if not os.path.exists(self.config.cfg_file):
                return None

            with open(self.config.cfg_file, "r") as f:
                data = json.load(f)

            # Validate topology structure
            if not isinstance(data, dict) or "hub" not in data or "spokes" not in data:
                raise NetworkConfigError("Topology file has invalid structure")

            return data
        except json.JSONDecodeError as e:
            raise NetworkConfigError(f"Topology file is corrupted: {str(e)}")
        except Exception as e:
            raise NetworkConfigError(f"Failed to load topology: {str(e)}")

    def save_topology(self, topology: Dict) -> None:
        """
        Save topology configuration atomically

        Args:
            topology: Topology data to save

        Raises:
            NetworkConfigError: If save operation fails
        """
        try:
            write_json_atomic(self.config.cfg_file, topology, 0o600)
        except Exception as e:
            raise NetworkConfigError(f"Failed to save topology: {str(e)}")

    def wipe_state(self) -> None:
        """
        Wipe all configuration state (topology, keys, configs)
        Used for factory reset operations
        """
        try:
            # Remove topology file
            if os.path.exists(self.config.cfg_file):
                os.remove(self.config.cfg_file)
        except Exception:
            pass

        # Clean keys and configs directories
        for directory in [self.config.keys_dir, self.config.wg_dir]:
            if os.path.isdir(directory):
                for root, dirs, files in os.walk(directory, topdown=False):
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
                    os.rmdir(directory)
                except Exception:
                    pass

    def generate_keypair(self, prefix: str) -> Tuple[str, str]:
        """
        Generate WireGuard keypair with secure file permissions

        Args:
            prefix: Key file prefix (validates for security)

        Returns:
            Tuple[str, str]: (private_key, public_key)

        Raises:
            WireGuardError: If key generation fails
            ValidationError: If prefix is invalid
        """
        WireGuardValidator.validate_key_prefix(prefix)

        try:
            self._ensure_directories()
            priv_path = os.path.join(self.config.keys_dir, f"{prefix}_private.key")
            pub_path = os.path.join(self.config.keys_dir, f"{prefix}_public.key")

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
        except subprocess.CalledProcessError as e:
            raise WireGuardError(f"Failed to generate WireGuard keys: {str(e)}")
        except Exception as e:
            raise WireGuardError(f"Key generation error: {str(e)}")

    def _hub_address_from_subnet(self, cidr: str) -> str:
        """
        Generate hub IP address from subnet safely

        Args:
            cidr: CIDR subnet notation

        Returns:
            str: Hub IP address with prefix

        Raises:
            NetworkConfigError: If subnet is invalid
        """
        NetworkValidator.validate_cidr(cidr)

        try:
            network = ipaddress.ip_network(cidr, strict=False)
            hosts = list(network.hosts())
            if not hosts:
                raise NetworkConfigError(f"Subnet {cidr} has no host addresses")
            return f"{hosts[0]}/{network.prefixlen}"  # first host
        except (ValueError, IndexError) as e:
            raise NetworkConfigError(
                f"Cannot generate hub address from {cidr}: {str(e)}"
            )

    def generate_hub_config(self, topology: Dict, hub_private_key: str) -> str:
        """
        Generate wg0.conf for the hub with route-safe configuration

        Args:
            topology: Topology configuration
            hub_private_key: Hub private key

        Returns:
            str: Path to generated config file

        Raises:
            WireGuardError: If config generation fails
        """
        try:
            self._ensure_directories()
            hub_addr = self._hub_address_from_subnet(topology["hub"]["subnet"])

            # Gather local IPv4 networks to avoid duplicate routes
            local_nets = self._get_local_networks()

            config_content = f"""[Interface]
Address = {hub_addr}
PrivateKey = {hub_private_key}
ListenPort = {topology["hub"].get("wg_port", self.config.WG_PORT)}
# Pure nftables; forwarding only.
PostUp   = sysctl -w net.ipv4.ip_forward=1
PostDown = :
"""

            # Add peer configurations
            for spoke in topology["spokes"]:
                vpn_ip = (spoke.get("vpn_ip") or "").strip()
                lan = (spoke.get("lan_subnet") or "").strip()
                parts = [vpn_ip] if vpn_ip else []
                if lan and lan not in local_nets:
                    parts.append(lan)

                config_content += f"""

[Peer]
PublicKey  = {spoke['public_key']}
AllowedIPs = {", ".join(parts)}
"""

            config_path = os.path.join(
                self.config.wg_dir, f"{self.config.WG_IFACE}.conf"
            )
            write_text_atomic(config_path, config_content, 0o600)

            return config_path
        except Exception as e:
            raise WireGuardError(f"Failed to generate hub config: {str(e)}")

    def _get_local_networks(self) -> set:
        """Get local IPv4 networks on this system to avoid route conflicts"""
        local_nets = set()
        try:
            import netifaces

            for iface in netifaces.interfaces():
                addrs = netifaces.ifaddresses(iface).get(netifaces.AF_INET, [])
                for addr_info in addrs:
                    ip = addr_info.get("addr")
                    mask = addr_info.get("netmask")
                    if ip and mask:
                        try:
                            network = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
                            local_nets.add(str(network))
                        except Exception:
                            pass
        except Exception:
            pass
        return local_nets

    def generate_spoke_config(
        self, spoke_name: str, spoke_data: Dict, topology: Dict
    ) -> str:
        """
        Generate configuration file for a spoke

        Args:
            spoke_name: Name of the spoke
            spoke_data: Spoke configuration data
            topology: Full topology data

        Returns:
            str: Path to generated config file

        Raises:
            WireGuardError: If config generation fails
        """
        WireGuardValidator.validate_spoke_name(spoke_name)

        try:
            self._ensure_directories()
            hub_pub = topology["hub"]["public_key"]
            hub_ip = topology["hub"]["public_ip"]
            hub_lans = topology["hub"].get("lan_subnets", []) or []

            # Determine allowed IPs based on mode
            if topology.get("mode", "hub-only") == "sdwan":
                allowed = [topology["hub"]["subnet"]] + hub_lans
            else:
                # Use full VPN subnet for mesh connectivity
                allowed = [topology["hub"]["subnet"]] + hub_lans

            # Load private key
            priv_key_path = os.path.join(
                self.config.keys_dir, f"{spoke_name}_private.key"
            )
            if not os.path.exists(priv_key_path):
                raise WireGuardError(f"Private key not found for spoke {spoke_name}")

            with open(priv_key_path, "r") as f:
                private_key = f.read().strip()

            config_content = f"""[Interface]
Address    = {spoke_data['vpn_ip']}
PrivateKey = {private_key}

[Peer]
PublicKey  = {hub_pub}
Endpoint   = {hub_ip}:{topology["hub"].get("wg_port", self.config.WG_PORT)}
AllowedIPs = {", ".join(allowed)}
PersistentKeepalive = 25
"""

            config_path = os.path.join(
                self.config.wg_dir, f"{spoke_name}-{self.config.WG_IFACE}.conf"
            )
            write_text_atomic(
                config_path, config_content, 0o644
            )  # Readable for QR codes

            return config_path
        except Exception as e:
            raise WireGuardError(
                f"Failed to generate spoke config for {spoke_name}: {str(e)}"
            )

    def restart_interface(self, config_path: str) -> Tuple[bool, str]:
        """
        Restart WireGuard interface with new configuration

        Args:
            config_path: Path to WireGuard configuration file

        Returns:
            Tuple[bool, str]: (success, message)
        """
        WireGuardValidator.validate_interface_name(self.config.WG_IFACE)

        try:
            unit = f"wg-up@{self.config.WG_IFACE}"

            # Try restart first
            cp = run_priv(
                ["systemctl", "--no-pager", "--plain", "try-restart", unit], check=False
            )
            if cp.returncode == 0:
                return True, "Interface restarted successfully"

            # If restart fails, reload daemon and restart
            run_priv(["systemctl", "--no-pager", "--plain", "daemon-reload"])
            cp = run_priv(
                ["systemctl", "--no-pager", "--plain", "restart", unit], check=False
            )

            if cp.returncode == 0:
                return True, "Interface restarted successfully"
            else:
                error_msg = cp.stderr or cp.stdout or "Unknown error"
                return False, f"Restart failed: {error_msg[:400]}"

        except Exception as e:
            return False, f"System error during restart: {str(e)}"
