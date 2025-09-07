"""
Legacy adapter to maintain backward compatibility with existing app.py
Provides the same interface as the original core.py functions
"""

import os
import sys

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ..config.settings import get_config  # noqa: E402
from ..core.exceptions import YggSecError  # noqa: E402
from ..services.wireguard_service import WireGuardService  # noqa: E402


class LegacyAdapter:
    """
    Adapter class that provides the original core.py interface
    while using the new service architecture underneath
    """

    def __init__(self):
        self.config = get_config()
        self.wg_service = WireGuardService(self.config)

        # Expose config values that were module-level constants
        self.ROOT_DIR = self.config.ROOT_DIR
        self.CFG_FILE = self.config.cfg_file
        self.KEYS_DIR = self.config.keys_dir
        self.WG_DIR = self.config.wg_dir
        self.WG_IFACE = self.config.WG_IFACE
        self.WG_PORT = self.config.WG_PORT
        self.HANDSHAKE_STALE_SECS = self.config.HANDSHAKE_STALE_SECS

    def topology_present(self):
        """Check if topology exists - legacy interface"""
        return self.wg_service.topology_exists()

    def load_topology(self):
        """Load topology - legacy interface"""
        try:
            return self.wg_service.load_topology()
        except YggSecError:
            return None  # Legacy behavior - return None on error

    def save_topology(self, topology):
        """Save topology - legacy interface"""
        try:
            self.wg_service.save_topology(topology)
        except YggSecError:
            pass  # Legacy behavior - fail silently

    def wipe_state(self):
        """Wipe state - legacy interface"""
        self.wg_service.wipe_state()

    def gen_keypair(self, prefix):
        """Generate keypair - legacy interface"""
        try:
            return self.wg_service.generate_keypair(prefix)
        except YggSecError as e:
            raise ValueError(str(e))  # Convert to ValueError for legacy compatibility

    def generate_hub_conf(self, topology, hub_priv):
        """Generate hub config - legacy interface"""
        try:
            return self.wg_service.generate_hub_config(topology, hub_priv)
        except YggSecError as e:
            raise RuntimeError(
                str(e)
            )  # Convert to RuntimeError for legacy compatibility

    def generate_spoke_conf(self, name, spoke, topology):
        """Generate spoke config - legacy interface"""
        try:
            return self.wg_service.generate_spoke_config(name, spoke, topology)
        except YggSecError as e:
            raise RuntimeError(
                str(e)
            )  # Convert to RuntimeError for legacy compatibility

    def restart_full(self, wg_conf_path):
        """Restart interface - legacy interface"""
        success, message = self.wg_service.restart_interface(wg_conf_path)
        if not success:
            raise RuntimeError(message)
        return success, message


# Create global instance for backward compatibility
_adapter = LegacyAdapter()

# Export all the functions that app.py expects
topology_present = _adapter.topology_present
load_topology = _adapter.load_topology
save_topology = _adapter.save_topology
wipe_state = _adapter.wipe_state
gen_keypair = _adapter.gen_keypair
generate_hub_conf = _adapter.generate_hub_conf
generate_spoke_conf = _adapter.generate_spoke_conf
restart_full = _adapter.restart_full

# Import missing functions from core.py that aren't in the adapter yet
from ..core.core import add_spoke  # noqa: F401, E402
from ..core.core import (
    add_hub_lan,
    delete_spoke,
    edit_public_ip,
    edit_vpn_subnet,
    regenerate_all,
    regenerate_hub_keys,
    regenerate_spoke_keys,
    remove_hub_lan,
)

# Export constants that app.py expects
ROOT_DIR = _adapter.ROOT_DIR
CFG_FILE = _adapter.CFG_FILE
KEYS_DIR = _adapter.KEYS_DIR
WG_DIR = _adapter.WG_DIR
WG_IFACE = _adapter.WG_IFACE
WG_PORT = _adapter.WG_PORT
HANDSHAKE_STALE_SECS = _adapter.HANDSHAKE_STALE_SECS
