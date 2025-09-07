"""
TOTP (Time-based One-Time Password) service for 2FA implementation
Provides secure two-factor authentication using Google Authenticator compatible tokens
"""

import logging
import os
import secrets
import time
from io import BytesIO
from typing import List, Optional

import pyotp
import qrcode

from ..config.settings import get_config
from ..core.exceptions import YggSecError
from ..utils.utils import read_json, write_json_atomic


class TOTPError(YggSecError):
    """TOTP-specific errors"""

    pass


class TOTPService:
    """
    TOTP service for two-factor authentication
    Handles secret generation, QR codes, token verification, and backup codes
    """

    def __init__(self, config=None):
        self.config = config or get_config()
        self.totp_file = os.path.join(self.config.ROOT_DIR, "totp_secrets.json")

    def _load_totp_data(self) -> dict:
        """Load TOTP data from secure file"""
        try:
            return read_json(self.totp_file)
        except Exception:
            return {}

    def _save_totp_data(self, data: dict) -> None:
        """Save TOTP data to secure file with restricted permissions"""
        try:
            write_json_atomic(self.totp_file, data, mode=0o600)
        except Exception as e:
            raise TOTPError(f"Failed to save TOTP data: {str(e)}")

    def is_2fa_enabled(self, username: str) -> bool:
        """Check if user has 2FA enabled"""
        data = self._load_totp_data()
        user_data = data.get(username, {})
        return user_data.get("enabled", False)

    def generate_secret(self, username: str) -> str:
        """Generate a new TOTP secret for user"""
        if not username:
            raise TOTPError("Username required for TOTP setup")

        # Generate cryptographically secure secret
        secret = pyotp.random_base32()

        # Store secret (but don't enable 2FA yet)
        data = self._load_totp_data()
        data[username] = {
            "secret": secret,
            "enabled": False,
            "backup_codes": self._generate_backup_codes(),
            "created": int(time.time()) if "time" in globals() else 0,
        }
        self._save_totp_data(data)

        return secret

    def get_secret(self, username: str) -> Optional[str]:
        """Get existing TOTP secret for user"""
        data = self._load_totp_data()
        user_data = data.get(username, {})
        return user_data.get("secret")

    def enable_2fa(self, username: str, verification_code: str) -> bool:
        """Enable 2FA after verifying setup code"""
        data = self._load_totp_data()
        user_data = data.get(username, {})

        if not user_data.get("secret"):
            raise TOTPError("No TOTP secret found - setup required first")

        # Verify the code before enabling
        if not self.verify_token(username, verification_code):
            return False

        # Enable 2FA
        user_data["enabled"] = True
        user_data["enabled_at"] = int(time.time()) if "time" in globals() else 0
        data[username] = user_data
        self._save_totp_data(data)

        logging.info(f"2FA enabled for user: {username}")
        return True

    def disable_2fa(self, username: str) -> bool:
        """Disable 2FA for user"""
        data = self._load_totp_data()

        if username in data:
            del data[username]
            self._save_totp_data(data)
            logging.info(f"2FA disabled for user: {username}")
            return True

        return False

    def verify_token(self, username: str, token: str) -> bool:
        """Verify TOTP token"""
        if not token or len(token.strip()) != 6:
            return False

        data = self._load_totp_data()
        user_data = data.get(username, {})
        secret = user_data.get("secret")

        if not secret:
            return False

        try:
            totp = pyotp.TOTP(secret)
            # Allow 1 window of tolerance for clock drift
            return totp.verify(token.strip(), valid_window=1)
        except Exception:
            return False

    def verify_backup_code(self, username: str, backup_code: str) -> bool:
        """Verify and consume backup code"""
        if not backup_code:
            return False

        data = self._load_totp_data()
        user_data = data.get(username, {})
        backup_codes = user_data.get("backup_codes", [])

        if backup_code.strip() in backup_codes:
            # Remove used backup code
            backup_codes.remove(backup_code.strip())
            user_data["backup_codes"] = backup_codes
            data[username] = user_data
            self._save_totp_data(data)

            logging.warning(f"Backup code used for user: {username}")
            return True

        return False

    def get_backup_codes(self, username: str) -> List[str]:
        """Get user's backup codes"""
        data = self._load_totp_data()
        user_data = data.get(username, {})
        return user_data.get("backup_codes", [])

    def regenerate_backup_codes(self, username: str) -> List[str]:
        """Generate new backup codes for user"""
        data = self._load_totp_data()

        if username not in data:
            raise TOTPError("User not found in TOTP data")

        new_codes = self._generate_backup_codes()
        data[username]["backup_codes"] = new_codes
        self._save_totp_data(data)

        logging.info(f"Backup codes regenerated for user: {username}")
        return new_codes

    def generate_qr_code(self, username: str, issuer_name: str = "YggSec") -> bytes:
        """Generate QR code for TOTP setup"""
        secret = self.get_secret(username)
        if not secret:
            raise TOTPError("No TOTP secret found for user")

        totp = pyotp.TOTP(secret)
        provisioning_uri = totp.provisioning_uri(name=username, issuer_name=issuer_name)

        # Generate QR code
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(provisioning_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        img_buffer = BytesIO()
        img.save(img_buffer, format="PNG")
        img_buffer.seek(0)

        return img_buffer.getvalue()

    def _generate_backup_codes(self, count: int = 8) -> List[str]:
        """Generate backup codes for account recovery"""
        codes = []
        for _ in range(count):
            # Generate 8-character alphanumeric codes
            code = "".join(
                secrets.choice("ABCDEFGHJKMNPQRSTUVWXYZ23456789") for _ in range(8)
            )
            codes.append(code)
        return codes

    def get_user_2fa_status(self, username: str) -> dict:
        """Get comprehensive 2FA status for user"""
        data = self._load_totp_data()
        user_data = data.get(username, {})

        return {
            "enabled": user_data.get("enabled", False),
            "has_secret": bool(user_data.get("secret")),
            "backup_codes_count": len(user_data.get("backup_codes", [])),
            "created": user_data.get("created"),
            "enabled_at": user_data.get("enabled_at"),
        }
