"""
Custom exceptions for YggSec following CLAUDE.md error handling principles
Provides clear error messages and graceful failure handling
"""


class YggSecError(Exception):
    """Base exception for YggSec errors"""
    
    def __init__(self, message: str, details: str = None):
        self.message = message
        self.details = details
        super().__init__(self.message)


class ValidationError(YggSecError):
    """Input validation error"""
    pass


class NetworkConfigError(YggSecError):
    """Network configuration error"""
    pass


class WireGuardError(YggSecError):
    """WireGuard operation error"""
    pass


class FirewallError(YggSecError):
    """Firewall operation error"""
    pass


class AuthenticationError(YggSecError):
    """Authentication error"""
    pass


class PermissionError(YggSecError):
    """Permission/authorization error"""
    pass


class ServiceError(YggSecError):
    """Service layer error"""
    pass


class ConfigurationError(YggSecError):
    """Configuration error"""
    pass