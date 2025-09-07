"""
Input validation utilities following CLAUDE.md security principles
Centralized validation logic for consistency and security
"""

import ipaddress
import re
from typing import Union

from .exceptions import ValidationError


class NetworkValidator:
    """Network-related input validation"""

    @staticmethod
    def validate_cidr(cidr: str) -> bool:
        """
        Validate CIDR notation with enhanced checks.

        Args:
            cidr: CIDR string to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If CIDR is invalid
        """
        if not cidr or not isinstance(cidr, str):
            raise ValidationError("CIDR cannot be empty")

        cidr = cidr.strip()
        if not cidr:
            raise ValidationError("CIDR cannot be empty")

        try:
            network = ipaddress.ip_network(cidr, strict=False)
            # Only allow reasonable IPv4 networks
            if network.version != 4:
                raise ValidationError("Only IPv4 networks are supported")
            # Reasonable prefix lengths for LANs
            if network.prefixlen < 8 or network.prefixlen > 30:
                raise ValidationError("Network prefix must be between /8 and /30")
            return True
        except (
            ValueError,
            ipaddress.AddressValueError,
            ipaddress.NetmaskValueError,
        ) as e:
            raise ValidationError(f"Invalid CIDR format: {str(e)}")

    @staticmethod
    def validate_ipv4_address(ip_str: str) -> bool:
        """
        Validate IPv4 address format.

        Args:
            ip_str: IP address string to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If IP is invalid
        """
        if not ip_str or not isinstance(ip_str, str):
            raise ValidationError("IP address cannot be empty")

        try:
            # Handle both IP addresses and CIDR notation (strip /32 if present)
            clean_ip = ip_str.strip()
            if "/" in clean_ip:
                clean_ip = clean_ip.split("/")[0]

            ipaddress.IPv4Address(clean_ip)  # Validate format
            return True
        except ValueError as e:
            raise ValidationError(f"Invalid IP address: {str(e)}")


class WireGuardValidator:
    """WireGuard-specific validation"""

    @staticmethod
    def validate_spoke_name(name: str) -> bool:
        """
        Validate spoke name for security.

        Args:
            name: Spoke name to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If name is invalid
        """
        if not name or not isinstance(name, str):
            raise ValidationError("Spoke name cannot be empty")

        name = name.strip()
        if not name:
            raise ValidationError("Spoke name cannot be empty")

        if not re.match(r"^[a-zA-Z0-9_-]{1,20}$", name):
            raise ValidationError(
                "Spoke name must be 1-20 characters: alphanumeric, dash, underscore only"
            )

        return True

    @staticmethod
    def validate_key_prefix(prefix: str) -> bool:
        """
        Validate key prefix for safe file naming.

        Args:
            prefix: Key prefix to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If prefix is invalid
        """
        if not prefix or not isinstance(prefix, str):
            raise ValidationError("Key prefix cannot be empty")

        prefix = prefix.strip()
        if not prefix:
            raise ValidationError("Key prefix cannot be empty")

        # Only allow alphanumeric, dash, underscore (same as spoke names)
        if not re.match(r"^[a-zA-Z0-9_-]{1,30}$", prefix):
            raise ValidationError(
                "Key prefix must be 1-30 characters: alphanumeric, dash, underscore only"
            )

        # Enhanced path traversal prevention with normalization
        import os

        normalized_prefix = os.path.normpath(prefix)
        if (
            normalized_prefix != prefix
            or ".." in normalized_prefix
            or "/" in normalized_prefix
            or "\\" in normalized_prefix
            or os.path.isabs(normalized_prefix)
        ):
            raise ValidationError("Key prefix contains invalid path traversal patterns")

        return True

    @staticmethod
    def validate_interface_name(iface: str) -> bool:
        """
        Validate WireGuard interface name.

        Args:
            iface: Interface name to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If interface name is invalid
        """
        if not iface or not isinstance(iface, str):
            raise ValidationError("Interface name cannot be empty")

        # Only allow wg followed by digits
        if not re.match(r"^wg[0-9]{1,2}$", iface):
            raise ValidationError("Interface name must be wg followed by 1-2 digits (e.g., wg0)")

        return True


class AuthValidator:
    """Authentication-related validation"""

    @staticmethod
    def validate_password(password: str, min_length: int = 8) -> bool:
        """
        Validate password strength.

        Args:
            password: Password to validate
            min_length: Minimum password length

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If password is invalid
        """
        if not password or not isinstance(password, str):
            raise ValidationError("Password cannot be empty")

        if len(password) < min_length:
            raise ValidationError(f"Password must be at least {min_length} characters")

        return True

    @staticmethod
    def validate_username(username: str) -> bool:
        """
        Validate username format.

        Args:
            username: Username to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If username is invalid
        """
        if not username or not isinstance(username, str):
            raise ValidationError("Username cannot be empty")

        username = username.strip()
        if not username:
            raise ValidationError("Username cannot be empty")

        # Allow reasonable username characters
        if not re.match(r"^[a-zA-Z0-9_.-]{1,50}$", username):
            raise ValidationError(
                "Username must be 1-50 characters: alphanumeric, dot, dash, underscore only"
            )

        return True


class FirewallValidator:
    """Firewall rule validation"""

    @staticmethod
    def validate_port(port: Union[str, int]) -> bool:
        """
        Validate network port number.

        Args:
            port: Port number to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If port is invalid
        """
        if port is None:
            return True  # Port is optional

        try:
            port_num = int(port)
            if port_num < 1 or port_num > 65535:
                raise ValidationError("Port must be between 1 and 65535")
            return True
        except (ValueError, TypeError):
            raise ValidationError("Port must be a valid integer")

    @staticmethod
    def validate_protocol(protocol: str) -> bool:
        """
        Validate network protocol.

        Args:
            protocol: Protocol to validate

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If protocol is invalid
        """
        if not protocol or not isinstance(protocol, str):
            raise ValidationError("Protocol cannot be empty")

        valid_protocols = ["tcp", "udp", "icmp", "all"]
        if protocol.lower() not in valid_protocols:
            raise ValidationError(f"Protocol must be one of: {', '.join(valid_protocols)}")

        return True
