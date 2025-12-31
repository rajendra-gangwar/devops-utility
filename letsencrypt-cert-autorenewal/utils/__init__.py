"""
Utility modules for Azure Key Vault Certificate Renewal.

This package contains:
- keyvault: Azure Key Vault operations
- certbot: Certbot renewal wrapper
- config_loader: Configuration loading and validation
- logger: Centralized logging setup
- helpers: Common utility functions
- notification: Notification system for renewal events
"""

from .logger import setup_logger, get_logger
from .config_loader import (
    load_config,
    Config,
    VaultConfig,
    NotificationsConfig,
    EmailNotificationConfig,
    TeamsNotificationConfig,
)
from .keyvault import KeyVaultClient, CertificateInfo
from .certbot import run_certbot_renewal, convert_to_pfx
from .helpers import (
    is_expiring_soon,
    is_letsencrypt_issuer,
    format_days_remaining,
    select_certificates,
    SelectionResult,
    SelectionReason,
    CertificateSelection,
)
from .notification import (
    NotificationManager,
    NotificationContext,
)

__all__ = [
    # Logger
    "setup_logger",
    "get_logger",
    # Config
    "load_config",
    "Config",
    "VaultConfig",
    "NotificationsConfig",
    "EmailNotificationConfig",
    "TeamsNotificationConfig",
    # Key Vault
    "KeyVaultClient",
    "CertificateInfo",
    # Certbot
    "run_certbot_renewal",
    "convert_to_pfx",
    # Helpers
    "is_expiring_soon",
    "is_letsencrypt_issuer",
    "format_days_remaining",
    "select_certificates",
    "SelectionResult",
    "SelectionReason",
    "CertificateSelection",
    # Notifications
    "NotificationManager",
    "NotificationContext",
]
