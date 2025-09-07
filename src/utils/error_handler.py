"""
Centralized error handling for YggSec application
Provides consistent error messaging, logging, and security-conscious error handling
"""

import logging
import re
import uuid
from typing import Tuple, Optional

try:
    from flask import current_app

    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False

try:
    from ..core.exceptions import (
        YggSecError,
        ValidationError,
        NetworkConfigError,
        WireGuardError,
        FirewallError,
        AuthenticationError,
        PermissionError,
        ServiceError,
        ConfigurationError,
    )
except ImportError:
    # Fallback if running outside of main app context
    class YggSecError(Exception):
        def __init__(self, message: str, details: str = None):
            self.message = message
            self.details = details
            super().__init__(self.message)

    class ValidationError(YggSecError):
        pass

    class NetworkConfigError(YggSecError):
        pass

    class WireGuardError(YggSecError):
        pass

    class FirewallError(YggSecError):
        pass

    class AuthenticationError(YggSecError):
        pass

    class PermissionError(YggSecError):
        pass

    class ServiceError(YggSecError):
        pass

    class ConfigurationError(YggSecError):
        pass


class ErrorHandler:
    """Centralized error handling with security-conscious message sanitization"""

    # Patterns to remove sensitive information from error messages
    SENSITIVE_PATTERNS = [
        r"/[a-zA-Z0-9/._-]*\.key",  # Private key file paths
        r"/[a-zA-Z0-9/._-]*\.conf",  # Config file paths
        r"password[=:]\s*\S+",  # Password values
        r"secret[=:]\s*\S+",  # Secret values
        r"token[=:]\s*\S+",  # Token values
        r"/opt/yggsec/[a-zA-Z0-9/._-]*",  # Internal paths
        r"/etc/[a-zA-Z0-9/._-]*",  # System paths
        r'File ".*?"',  # Python file paths in tracebacks
    ]

    # User-friendly error messages by exception type
    ERROR_MESSAGES = {
        ValidationError: "Invalid input provided",
        NetworkConfigError: "Network configuration error occurred",
        WireGuardError: "VPN operation failed",
        FirewallError: "Firewall operation failed",
        AuthenticationError: "Authentication failed",
        PermissionError: "Access denied",
        ServiceError: "Service operation failed",
        ConfigurationError: "Configuration error occurred",
    }

    @classmethod
    def handle_error(
        cls,
        error: Exception,
        context: str,
        operation: str = None,
        sanitize: bool = True,
    ) -> Tuple[str, str]:
        """
        Handle an error with consistent logging and user messaging

        Args:
            error: The exception that occurred
            context: Context where error occurred (e.g., "firewall_add_rule")
            operation: User-facing operation name (e.g., "adding firewall rule")
            sanitize: Whether to sanitize user message (default: True)

        Returns:
            Tuple of (user_message, correlation_id)
        """

        # Generate correlation ID for error tracking
        correlation_id = str(uuid.uuid4())[:8]

        # Get user-friendly message
        user_message = cls._get_user_message(error, operation, sanitize)

        # Create detailed log message
        log_message = cls._create_log_message(error, context, correlation_id)

        # Log the error
        cls._log_error(log_message, error)

        return user_message, correlation_id

    @classmethod
    def _get_user_message(
        cls, error: Exception, operation: str = None, sanitize: bool = True
    ) -> str:
        """Generate user-friendly error message"""

        # Check if it's a known YggSec exception
        for exc_type, message in cls.ERROR_MESSAGES.items():
            if isinstance(error, exc_type):
                if operation:
                    return f"Failed {operation}: {message}"
                return message

        # For unknown exceptions, provide generic message
        if operation:
            return f"Failed {operation}: An unexpected error occurred"

        # If it's a YggSec error with a safe message, use it
        if isinstance(error, YggSecError) and hasattr(error, "message"):
            message = error.message
            if sanitize:
                message = cls._sanitize_message(message)
            return message

        return "An unexpected error occurred"

    @classmethod
    def _sanitize_message(cls, message: str) -> str:
        """Remove sensitive information from error messages"""
        sanitized = message

        for pattern in cls.SENSITIVE_PATTERNS:
            sanitized = re.sub(pattern, "[REDACTED]", sanitized, flags=re.IGNORECASE)

        return sanitized

    @classmethod
    def _create_log_message(
        cls, error: Exception, context: str, correlation_id: str
    ) -> str:
        """Create detailed log message for internal debugging"""
        error_type = type(error).__name__
        error_msg = str(error)

        return f"[{correlation_id}] {error_type} in {context}: {error_msg}"

    @classmethod
    def _log_error(cls, message: str, error: Exception):
        """Log error with appropriate level"""
        try:
            # Use Flask's logger if available
            if FLASK_AVAILABLE and "current_app" in globals():
                try:
                    if isinstance(error, (AuthenticationError, PermissionError)):
                        current_app.logger.warning(message)
                    elif isinstance(error, ValidationError):
                        current_app.logger.info(message)
                    else:
                        current_app.logger.error(message)
                    return
                except RuntimeError:
                    # Flask app context not available
                    pass

            # Fallback to standard logging
            logging.error(message)
        except Exception:
            # Last resort - print to stderr
            print(f"ERROR: {message}", file=__import__("sys").stderr)


def handle_api_error(error: Exception, operation: str = None) -> Tuple[str, str]:
    """
    Convenience function for API error handling

    Returns:
        Tuple of (user_message, correlation_id)
    """
    import inspect

    # Get calling function name for context
    frame = inspect.currentframe().f_back
    context = f"{frame.f_code.co_name}"

    return ErrorHandler.handle_error(error, context, operation, sanitize=True)


def handle_service_error(
    error: Exception, service: str, operation: str = None
) -> Tuple[str, str]:
    """
    Convenience function for service layer error handling

    Args:
        error: The exception
        service: Service name (e.g., "wireguard", "firewall")
        operation: Operation being performed

    Returns:
        Tuple of (user_message, correlation_id)
    """
    context = f"{service}_service"
    return ErrorHandler.handle_error(error, context, operation, sanitize=True)
