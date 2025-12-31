"""
Configuration loading, validation, and parsing.

Loads configuration from YAML files and provides typed access
to configuration values.
"""

import os
import re
from pathlib import Path
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

import yaml

from .logger import get_logger


class ConfigurationError(Exception):
    """Raised when configuration is invalid or missing."""
    pass


# Default AWS region (can be overridden by config, env var, or CLI arg)
DEFAULT_AWS_REGION = "eu-west-1"


@dataclass
class AWSAccountConfig:
    """AWS account configuration for Route53."""
    account_id: str
    hosted_zones: List[str]
    role_arn: Optional[str] = None
    region: str = DEFAULT_AWS_REGION


@dataclass
class AzureZoneConfig:
    """Azure DNS zone configuration."""
    zone: str
    resource_group: str


@dataclass
class AzureSubscriptionConfig:
    """Azure subscription configuration for DNS."""
    subscription_id: str
    zones: List[AzureZoneConfig] = field(default_factory=list)


@dataclass
class DNSProvidersConfig:
    """DNS provider configurations."""
    route53_accounts: Dict[str, AWSAccountConfig] = field(default_factory=dict)
    azure_subscriptions: Dict[str, AzureSubscriptionConfig] = field(default_factory=dict)

    def find_zone_for_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """
        Find the DNS zone configuration for a given domain.

        Searches all configured DNS providers (Route53 and Azure) to find
        the matching zone. Uses longest suffix match to find the best zone.

        Args:
            domain: Domain name to find zone for

        Returns:
            Dict with provider config or None if not found
        """
        # Remove wildcard prefix
        if domain.startswith("*."):
            domain = domain[2:]

        best_match = None
        best_length = 0

        # Search Route53 accounts
        for account_id, account in self.route53_accounts.items():
            for zone in account.hosted_zones:
                if domain == zone or domain.endswith(f".{zone}"):
                    if len(zone) > best_length:
                        best_match = {
                            "provider": "route53",
                            "account_id": account_id,
                            "zone": zone,
                            "role_arn": account.role_arn,
                            "region": account.region,
                        }
                        best_length = len(zone)

        # Search Azure subscriptions
        for sub_id, sub in self.azure_subscriptions.items():
            for zone_config in sub.zones:
                zone = zone_config.zone
                if domain == zone or domain.endswith(f".{zone}"):
                    if len(zone) > best_length:
                        best_match = {
                            "provider": "azure",
                            "subscription_id": sub_id,
                            "zone": zone,
                            "resource_group": zone_config.resource_group,
                        }
                        best_length = len(zone)

        return best_match


@dataclass
class VaultConfig:
    """Azure Key Vault configuration.

    Certificate selection behavior:
    - ignore_certificates: Always takes precedence. These certificates are NEVER processed.
    - include_certificates: If empty/not provided, all certificates are processed (minus ignored).
                           If specified, ONLY these certificates are processed (minus ignored).
    """
    name: str
    url: str
    ignore_certificates: List[str] = field(default_factory=list)
    include_certificates: List[str] = field(default_factory=list)


@dataclass
class EmailNotificationConfig:
    """Email notification configuration."""
    enabled: bool = False
    from_email: str = ""
    to_emails: List[str] = field(default_factory=list)
    template_path: Optional[str] = None


@dataclass
class TeamsNotificationConfig:
    """Teams notification configuration."""
    enabled: bool = False
    webhook_url: Optional[str] = None
    template_path: Optional[str] = None


@dataclass
class NotificationsConfig:
    """Notification channels configuration."""
    email: EmailNotificationConfig = field(default_factory=EmailNotificationConfig)
    teams: TeamsNotificationConfig = field(default_factory=TeamsNotificationConfig)


@dataclass
class Settings:
    """Global settings."""
    expiration_threshold_days: int = 10
    letsencrypt_email: str = ""
    continue_on_error: bool = True
    cleanup_after_upload: bool = True
    dry_run: bool = False
    certbot_work_dir: str = "/tmp/certbot"
    certbot_logs_dir: str = "/tmp/certbot-logs"
    certbot_config_dir: str = "/tmp/certbot-config"
    # Certificate key configuration
    key_type: str = "rsa"  # "rsa" or "ecdsa"
    rsa_key_size: int = 2048  # 2048, 3072, or 4096
    elliptic_curve: str = "secp384r1"  # secp256r1 or secp384r1


@dataclass
class Config:
    """Root configuration object."""
    settings: Settings
    dns_providers: DNSProvidersConfig
    vaults: List[VaultConfig]
    notifications: NotificationsConfig = field(default_factory=NotificationsConfig)


def _expand_env_vars(value: Any) -> Any:
    """
    Expand environment variables in string values.

    Supports ${VAR_NAME} syntax.

    Args:
        value: Value to expand (string, dict, or list)

    Returns:
        Value with environment variables expanded
    """
    if isinstance(value, str):
        # Match ${VAR_NAME} pattern
        pattern = r"\$\{([^}]+)\}"

        def replace(match):
            var_name = match.group(1)
            return os.environ.get(var_name, match.group(0))

        return re.sub(pattern, replace, value)

    elif isinstance(value, dict):
        return {k: _expand_env_vars(v) for k, v in value.items()}

    elif isinstance(value, list):
        return [_expand_env_vars(item) for item in value]

    return value


def _parse_dns_providers(data: Dict[str, Any]) -> DNSProvidersConfig:
    """
    Parse DNS providers configuration.

    Args:
        data: Raw DNS providers data from YAML

    Returns:
        DNSProvidersConfig instance
    """
    config = DNSProvidersConfig()

    # Parse Route53 accounts
    route53_data = data.get("route53", {}).get("accounts", {})
    for account_id, account_data in route53_data.items():
        config.route53_accounts[account_id] = AWSAccountConfig(
            account_id=account_id,
            hosted_zones=account_data.get("hosted_zones", []),
            role_arn=account_data.get("role_arn"),
            region=account_data.get("region", DEFAULT_AWS_REGION),
        )

    # Parse Azure subscriptions
    azure_data = data.get("azure", {}).get("subscriptions", {})
    for sub_id, sub_data in azure_data.items():
        zones_data = sub_data.get("zones", [])
        zones = []
        for zone_entry in zones_data:
            if isinstance(zone_entry, dict):
                # New format: {zone: "example.com", resource_group: "rg-name"}
                zones.append(AzureZoneConfig(
                    zone=zone_entry.get("zone", ""),
                    resource_group=zone_entry.get("resource_group", ""),
                ))
            else:
                raise ConfigurationError(
                    f"Invalid zone format in Azure subscription {sub_id}. "
                    "Each zone must have 'zone' and 'resource_group' fields."
                )

        config.azure_subscriptions[sub_id] = AzureSubscriptionConfig(
            subscription_id=sub_id,
            zones=zones,
        )

    return config


def _parse_vaults(data: List[Dict[str, Any]]) -> List[VaultConfig]:
    """
    Parse vault configurations.

    Args:
        data: Raw vault list from YAML

    Returns:
        List of VaultConfig instances
    """
    vaults = []

    for vault_data in data:
        vault = VaultConfig(
            name=vault_data.get("name", ""),
            url=vault_data.get("url", ""),
            ignore_certificates=vault_data.get("ignore_certificates", []),
            include_certificates=vault_data.get("include_certificates", []),
        )

        # Validate vault config
        if not vault.name:
            raise ConfigurationError("Vault name is required")
        if not vault.url:
            raise ConfigurationError(f"Vault URL is required for {vault.name}")
        if not vault.url.startswith("https://"):
            raise ConfigurationError(f"Vault URL must start with https:// for {vault.name}")

        vaults.append(vault)

    return vaults


def _parse_settings(data: Dict[str, Any]) -> Settings:
    """
    Parse settings configuration.

    Args:
        data: Raw settings data from YAML

    Returns:
        Settings instance
    """
    # Parse key configuration
    key_type = data.get("key_type", "rsa").lower()
    rsa_key_size = data.get("rsa_key_size", 2048)
    elliptic_curve = data.get("elliptic_curve", "secp384r1").lower()

    settings = Settings(
        expiration_threshold_days=data.get("expiration_threshold_days", 10),
        letsencrypt_email=data.get("letsencrypt_email", ""),
        continue_on_error=data.get("continue_on_error", True),
        cleanup_after_upload=data.get("cleanup_after_upload", True),
        dry_run=data.get("dry_run", False),
        certbot_work_dir=data.get("certbot_work_dir", "/tmp/certbot"),
        certbot_logs_dir=data.get("certbot_logs_dir", "/tmp/certbot-logs"),
        certbot_config_dir=data.get("certbot_config_dir", "/tmp/certbot-config"),
        key_type=key_type,
        rsa_key_size=rsa_key_size,
        elliptic_curve=elliptic_curve,
    )

    # Validate settings
    if settings.expiration_threshold_days < 1:
        raise ConfigurationError("expiration_threshold_days must be at least 1")
    if settings.expiration_threshold_days > 90:
        raise ConfigurationError("expiration_threshold_days should not exceed 90")
    # Note: letsencrypt_email is optional. If empty, certbot will use --register-unsafely-without-email

    # Validate key configuration
    valid_key_types = ["rsa", "ecdsa"]
    if settings.key_type not in valid_key_types:
        raise ConfigurationError(
            f"Invalid key_type '{settings.key_type}'. Must be one of: {', '.join(valid_key_types)}"
        )

    valid_rsa_sizes = [2048, 3072, 4096]
    if settings.rsa_key_size not in valid_rsa_sizes:
        raise ConfigurationError(
            f"Invalid rsa_key_size '{settings.rsa_key_size}'. Must be one of: {', '.join(map(str, valid_rsa_sizes))}"
        )

    valid_curves = ["secp256r1", "secp384r1"]
    if settings.elliptic_curve not in valid_curves:
        raise ConfigurationError(
            f"Invalid elliptic_curve '{settings.elliptic_curve}'. Must be one of: {', '.join(valid_curves)}"
        )

    return settings


def _parse_notifications(data: Dict[str, Any]) -> NotificationsConfig:
    """
    Parse notifications configuration.

    Args:
        data: Raw notifications data from YAML

    Returns:
        NotificationsConfig instance
    """
    # Parse email configuration
    email_data = data.get("email", {})
    to_emails = email_data.get("to_emails", [])
    if isinstance(to_emails, str):
        to_emails = [to_emails]

    email_config = EmailNotificationConfig(
        enabled=email_data.get("enabled", False),
        from_email=email_data.get("from_email", ""),
        to_emails=to_emails,
        template_path=email_data.get("template_path"),
    )

    # Parse Teams configuration
    teams_data = data.get("teams", {})
    teams_config = TeamsNotificationConfig(
        enabled=teams_data.get("enabled", False),
        webhook_url=teams_data.get("webhook_url"),
        template_path=teams_data.get("template_path"),
    )

    return NotificationsConfig(
        email=email_config,
        teams=teams_config,
    )


def load_config(config_path: str) -> Config:
    """
    Load and validate configuration from a YAML file.

    Args:
        config_path: Path to the configuration file

    Returns:
        Validated Config instance

    Raises:
        ConfigurationError: If configuration is invalid
    """
    logger = get_logger()
    path = Path(config_path)

    # Check file exists
    if not path.exists():
        raise ConfigurationError(f"Configuration file not found: {config_path}")

    # Check file extension
    if path.suffix not in (".yaml", ".yml"):
        raise ConfigurationError(
            f"Configuration file must be YAML (.yaml or .yml): {config_path}"
        )

    # Load YAML
    try:
        with open(path, "r") as f:
            raw_data = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise ConfigurationError(f"Invalid YAML in configuration file: {e}")
    except IOError as e:
        raise ConfigurationError(f"Failed to read configuration file: {e}")

    if not raw_data:
        raise ConfigurationError("Configuration file is empty")

    # Expand environment variables
    data = _expand_env_vars(raw_data)

    # Validate required sections
    if "settings" not in data:
        raise ConfigurationError("Missing 'settings' section in configuration")
    if "vaults" not in data:
        raise ConfigurationError("Missing 'vaults' section in configuration")

    # Parse sections
    settings = _parse_settings(data.get("settings", {}))
    dns_providers = _parse_dns_providers(data.get("dns_providers", {}))
    vaults = _parse_vaults(data.get("vaults", []))
    notifications = _parse_notifications(data.get("notifications", {}))

    if not vaults:
        raise ConfigurationError("At least one vault must be configured")

    logger.info(f"Loaded configuration from {config_path}")
    logger.info(f"  Vaults: {len(vaults)}")
    logger.info(f"  AWS accounts: {len(dns_providers.route53_accounts)}")
    logger.info(f"  Azure subscriptions: {len(dns_providers.azure_subscriptions)}")

    # Log notification configuration
    enabled_channels = []
    if notifications.email.enabled:
        enabled_channels.append("email")
    if notifications.teams.enabled:
        enabled_channels.append("teams")
    if enabled_channels:
        logger.info(f"  Notifications: {', '.join(enabled_channels)}")
    else:
        logger.info("  Notifications: disabled")

    return Config(
        settings=settings,
        dns_providers=dns_providers,
        vaults=vaults,
        notifications=notifications,
    )
