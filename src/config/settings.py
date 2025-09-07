"""
Configuration management with centralized settings
Environment variable support and validation for security settings
"""

import os
import tempfile
from typing import Optional


class BaseConfig:
    """Base configuration class with common settings"""

    # Application Settings
    SECRET_KEY: str = os.environ.get("SECRET_KEY", "")
    DEBUG: bool = os.environ.get("DEBUG", "False").lower() == "true"

    # YggSec Core Settings
    ROOT_DIR: str = os.environ.get("YGGSEC_ROOT", "/opt/yggsec")
    WG_IFACE: str = "wg0"
    WG_PORT: int = 51820
    HANDSHAKE_STALE_SECS: int = 180

    # Security Settings
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_HTTPONLY: bool = True
    SESSION_COOKIE_SAMESITE: str = "Lax"
    PERMANENT_SESSION_LIFETIME: int = 3600
    WTF_CSRF_TIME_LIMIT: int = 3600

    # Rate Limiting
    RATE_LIMIT_DEFAULT: str = "100 per hour"
    LOGIN_RATE_LIMIT: str = "5 per minute"
    PING_RATE_LIMIT_REQUESTS: int = 10
    PING_RATE_LIMIT_WINDOW: int = 60

    # Password Policy
    MIN_PASSWORD_LENGTH: int = 8

    @property
    def cfg_file(self) -> str:
        """Path to topology configuration file"""
        return os.path.join(self.ROOT_DIR, "topology.json")

    @property
    def keys_dir(self) -> str:
        """Path to WireGuard keys directory"""
        return os.path.join(self.ROOT_DIR, "keys")

    @property
    def wg_dir(self) -> str:
        """Path to WireGuard configurations directory"""
        return os.path.join(self.ROOT_DIR, "configs")

    @property
    def admins_file(self) -> str:
        """Path to admin users file"""
        return os.path.join(self.ROOT_DIR, "configs", "admins.json")

    @property
    def ping_results_file(self) -> str:
        """Path to ping results file"""
        return os.path.join(self.ROOT_DIR, "configs", "ping_results.json")

    def validate(self) -> None:
        """Validate configuration settings"""
        if not self.SECRET_KEY:
            raise ValueError("SECRET_KEY environment variable must be set")

        if self.MIN_PASSWORD_LENGTH < 8:
            raise ValueError("Minimum password length must be at least 8 characters")


class DevelopmentConfig(BaseConfig):
    """Development configuration"""

    DEBUG = True


class ProductionConfig(BaseConfig):
    """Production configuration"""

    DEBUG = False


class TestingConfig(BaseConfig):
    """Testing configuration"""

    DEBUG = True
    ROOT_DIR = os.environ.get("YGGSEC_ROOT_DIR", os.path.join(tempfile.gettempdir(), "yggsec-test"))


# Configuration factory
def get_config(env: Optional[str] = None) -> BaseConfig:
    """Get configuration based on environment"""
    if env is None:
        env = os.environ.get("FLASK_ENV", "production")

    config_map = {
        "development": DevelopmentConfig(),
        "production": ProductionConfig(),
        "testing": TestingConfig(),
    }

    config = config_map.get(env, ProductionConfig())
    config.validate()
    return config
