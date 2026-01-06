#!/usr/bin/env python3
"""
Azure Key Vault Certificate Renewal Automation - Main Entry Point.

This script orchestrates the renewal of Let's Encrypt certificates stored
in Azure Key Vaults. It supports both automatic mode (scanning all configured
vaults) and manual mode (renewing a specific certificate).

It also supports creating new certificates and uploading them to Key Vault.

Usage:
    # Automatic mode - scan all vaults and renew expiring certs
    python main.py --auto

    # Manual mode - renew a specific certificate
    python main.py --vault-name my-vault --certificate-name my-cert

    # Create a new certificate and upload to Key Vault
    python main.py --task create --san "example.com,www.example.com" \\
        --vault-url https://my-vault.vault.azure.net/ \\
        --subscription <subscription-id> --cert-name my-cert

    # Dry run (no actual changes)
    python main.py --auto --dry-run
"""

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any, FrozenSet
from dataclasses import dataclass, field, asdict
from enum import Enum

from utils.logger import setup_logger, get_logger
from utils.config_loader import load_config, Config, VaultConfig, ConfigurationError
from utils.keyvault import (
    KeyVaultClient,
    get_certificate_details,
    upload_certificate,
    CertificateInfo,
)
from utils.certbot import run_certbot_renewal, run_certbot_create, convert_to_pfx, get_certificate_expiry
from utils.helpers import (
    is_expiring_soon,
    is_letsencrypt_issuer,
    format_days_remaining,
    select_certificates,
    SelectionReason,
    normalize_san_signature,
    generate_certificate_filename,
    save_pfx_artifact,
)
from utils.notification import NotificationManager, NotificationContext


class RenewalStatus(Enum):
    """Status of a certificate renewal attempt."""
    RENEWED = "renewed"
    SKIPPED = "skipped"
    FAILED = "failed"
    IGNORED = "ignored"


@dataclass
class CertificateRecord:
    """
    Record of a certificate discovered during inventory scan.

    Used for global certificate inventory and duplicate detection.
    """
    vault_name: str
    vault_url: str
    cert_name: str
    common_name: str
    san_list: List[str]
    san_signature: FrozenSet[str]  # Normalized SANs for comparison
    expiry_date: Optional[datetime]
    thumbprint: Optional[str]
    needs_renewal: bool
    issuer: Optional[str] = None

    def __hash__(self):
        """Hash based on vault and cert name for set operations."""
        return hash((self.vault_name, self.cert_name))

    def __eq__(self, other):
        """Equality based on vault and cert name."""
        if not isinstance(other, CertificateRecord):
            return False
        return self.vault_name == other.vault_name and self.cert_name == other.cert_name


def get_pfx_password(args_password: Optional[str] = None) -> Optional[str]:
    """
    Get PFX password from command-line argument, environment variable, or default to None.

    Priority:
    1. Command-line argument (--pfx-password)
    2. Environment variable (PFX_PASSWORD)
    3. None (empty password)

    Args:
        args_password: Password from command-line argument

    Returns:
        Password string or None for empty password
    """
    if args_password is not None:
        return args_password
    return os.environ.get("PFX_PASSWORD")


@dataclass
class RenewalResult:
    """Result of a certificate renewal attempt."""
    vault_name: str
    certificate_name: str
    status: RenewalStatus
    message: str
    domains: Optional[List[str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "vault_name": self.vault_name,
            "certificate_name": self.certificate_name,
            "status": self.status.value.upper(),
            "message": self.message,
            "domains": self.domains,
        }


@dataclass
class VaultSummary:
    """Summary of processing results for a single vault."""
    name: str
    url: str
    certificates_discovered: int = 0
    certificates_selected: int = 0
    certificates_ignored: int = 0
    certificates_excluded: int = 0
    renewed: int = 0
    skipped: int = 0
    failed: int = 0
    error: Optional[str] = None  # Vault-level error (e.g., access denied)
    results: List[RenewalResult] = field(default_factory=list)

    @property
    def has_failures(self) -> bool:
        """Check if vault had any failures."""
        return self.failed > 0 or self.error is not None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "name": self.name,
            "url": self.url,
            "certificates_discovered": self.certificates_discovered,
            "certificates_selected": self.certificates_selected,
            "certificates_ignored": self.certificates_ignored,
            "certificates_excluded": self.certificates_excluded,
            "renewed": self.renewed,
            "skipped": self.skipped,
            "failed": self.failed,
            "error": self.error,
            "results": [r.to_dict() for r in self.results],
        }


@dataclass
class ExecutionSummary:
    """Complete execution summary for the entire run."""
    task: str  # "renew", "create", or "single"
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: Optional[str] = None
    dry_run: bool = False
    use_staging: bool = False  # True if using Let's Encrypt staging environment
    success: bool = True
    exit_code: int = 0

    # Global counts
    total_vaults: int = 0
    total_certificates_evaluated: int = 0
    total_renewed: int = 0
    total_skipped: int = 0
    total_ignored: int = 0
    total_failed: int = 0

    # Vault details
    vaults: List[VaultSummary] = field(default_factory=list)

    # Errors that occurred outside vault processing
    global_errors: List[str] = field(default_factory=list)

    def add_vault_summary(self, vault_summary: VaultSummary) -> None:
        """Add a vault summary and update global counts."""
        self.vaults.append(vault_summary)
        self.total_vaults += 1
        self.total_certificates_evaluated += len(vault_summary.results)
        self.total_renewed += vault_summary.renewed
        self.total_skipped += vault_summary.skipped
        self.total_ignored += vault_summary.certificates_ignored
        self.total_failed += vault_summary.failed

        # Mark as failed if vault had failures
        if vault_summary.has_failures:
            self.success = False
            self.exit_code = 1

    def add_result(self, result: RenewalResult, vault_name: str = "default") -> None:
        """Add a single result (for create/single certificate mode)."""
        # Find or create vault summary
        vault_summary = None
        for vs in self.vaults:
            if vs.name == vault_name:
                vault_summary = vs
                break

        if vault_summary is None:
            vault_summary = VaultSummary(name=vault_name, url="")
            self.vaults.append(vault_summary)
            self.total_vaults += 1

        vault_summary.results.append(result)
        self.total_certificates_evaluated += 1

        if result.status == RenewalStatus.RENEWED:
            vault_summary.renewed += 1
            self.total_renewed += 1
        elif result.status == RenewalStatus.SKIPPED:
            vault_summary.skipped += 1
            self.total_skipped += 1
        elif result.status == RenewalStatus.IGNORED:
            vault_summary.certificates_ignored += 1
            self.total_ignored += 1
        elif result.status == RenewalStatus.FAILED:
            vault_summary.failed += 1
            self.total_failed += 1
            self.success = False
            self.exit_code = 1

    def add_global_error(self, error: str) -> None:
        """Add a global error (outside vault processing)."""
        self.global_errors.append(error)
        self.success = False
        self.exit_code = 1

    def finalize(self) -> None:
        """Mark execution as complete."""
        self.completed_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "task": self.task,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "dry_run": self.dry_run,
            "use_staging": self.use_staging,
            "letsencrypt_environment": "staging" if self.use_staging else "production",
            "success": self.success,
            "exit_code": self.exit_code,
            "summary": {
                "total_vaults": self.total_vaults,
                "total_certificates_evaluated": self.total_certificates_evaluated,
                "total_renewed": self.total_renewed,
                "total_skipped": self.total_skipped,
                "total_ignored": self.total_ignored,
                "total_failed": self.total_failed,
            },
            "vaults": [v.to_dict() for v in self.vaults],
            "global_errors": self.global_errors,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)


def parse_arguments() -> argparse.Namespace:
    """
    Parse command-line arguments.

    Returns:
        Parsed arguments namespace
    """
    parser = argparse.ArgumentParser(
        description="Azure Key Vault Certificate Renewal Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --auto                           # Scan all vaults, renew expiring certs
  %(prog)s --auto --dry-run                 # Test mode, no changes
  %(prog)s --vault-name kv --cert-name c1   # Renew specific certificate

  # Create a new certificate:
  %(prog)s --task create --san "example.com,www.example.com" \\
           --vault-url https://myvault.vault.azure.net/ \\
           --subscription <sub-id> --cert-name my-cert
        """,
    )

    # Task selection (create new cert or renew existing)
    parser.add_argument(
        "--task",
        type=str,
        choices=["create", "renew"],
        default=None,
        help="Task type: 'create' for new certificate, 'renew' for renewal (default: renew)",
    )

    # Create task options
    parser.add_argument(
        "--san",
        type=str,
        help="Create mode: comma-separated list of SANs (Subject Alternative Names)",
    )
    parser.add_argument(
        "--vault-url",
        type=str,
        help="Create mode: Key Vault URL (e.g., https://myvault.vault.azure.net/)",
    )
    parser.add_argument(
        "--subscription",
        type=str,
        help="Create mode: Azure subscription ID for the Key Vault",
    )

    # Mode selection for renewal task
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument(
        "--auto",
        action="store_true",
        help="Automatic mode: scan all configured vaults for expiring certificates",
    )
    mode_group.add_argument(
        "--vault-name",
        type=str,
        help="Manual mode: specify the vault name containing the certificate",
    )

    # Manual mode options (shared with create mode for cert-name)
    parser.add_argument(
        "--certificate-name",
        "--cert-name",
        type=str,
        dest="certificate_name",
        help="Name of the certificate (for create or manual renew mode)",
    )

    # Common options
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Path to configuration file (default: config.yaml)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Test mode: don't make actual changes",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        help="Override expiration threshold (days)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose/debug logging",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output",
    )
    parser.add_argument(
        "--aws-region",
        type=str,
        default=None,
        help="Override AWS region (default: eu-west-1 or AWS_DEFAULT_REGION env var)",
    )
    parser.add_argument(
        "--pfx-password",
        type=str,
        default=None,
        help="Password for PFX certificate (falls back to PFX_PASSWORD env var, then empty)",
    )
    parser.add_argument(
        "--json-summary",
        action="store_true",
        help="Output machine-readable JSON summary at the end of execution",
    )
    parser.add_argument(
        "--artifact-dir",
        type=str,
        default=None,
        help="Directory to save PFX certificates for GitHub artifacts (e.g., ./artifacts)",
    )

    # Key type configuration (overrides config.yaml)
    parser.add_argument(
        "--key-type",
        type=str,
        choices=["rsa", "ecdsa"],
        default=None,
        help="Certificate key type: rsa or ecdsa (overrides config.yaml)",
    )
    parser.add_argument(
        "--rsa-key-size",
        type=int,
        choices=[2048, 3072, 4096],
        default=None,
        help="RSA key size: 2048, 3072, or 4096 (overrides config.yaml)",
    )
    parser.add_argument(
        "--elliptic-curve",
        type=str,
        choices=["secp256r1", "secp384r1"],
        default=None,
        help="ECDSA curve: secp256r1 or secp384r1 (overrides config.yaml)",
    )

    # Let's Encrypt environment selection
    parser.add_argument(
        "--use-staging",
        action="store_true",
        help="Use Let's Encrypt staging environment for testing (avoids production rate limits)",
    )

    args = parser.parse_args()

    # Validate arguments based on task/mode
    if args.task == "create":
        # Create mode validation
        if not args.san:
            parser.error("--task create requires --san")
        if not args.vault_url:
            parser.error("--task create requires --vault-url")
        if not args.subscription:
            parser.error("--task create requires --subscription")
        if not args.certificate_name:
            parser.error("--task create requires --cert-name")
    else:
        # Renew mode validation (default behavior)
        if not args.auto and not args.vault_name:
            parser.error("Either --auto or --vault-name is required for renewal mode")
        if args.vault_name and not args.certificate_name:
            parser.error("Manual mode requires --certificate-name")

    return args


def build_certificate_inventory(
    config: Config,
    threshold_days: int,
) -> Dict[FrozenSet[str], List[CertificateRecord]]:
    """
    Scan all configured vaults and build a global certificate inventory.

    Groups certificates by their SAN signature for duplicate detection.

    Args:
        config: Global configuration with vault settings
        threshold_days: Number of days before expiration to mark as needs_renewal

    Returns:
        Dictionary mapping SAN_SIGNATURE → [CertificateRecord, ...]
    """
    logger = get_logger()
    inventory: Dict[FrozenSet[str], List[CertificateRecord]] = defaultdict(list)

    logger.info("=" * 60)
    logger.info("PHASE 1: Building Global Certificate Inventory")
    logger.info("=" * 60)

    for vault_config in config.vaults:
        logger.info(f"\nScanning vault: {vault_config.name}")
        logger.info(f"  URL: {vault_config.url}")

        try:
            # Connect to Key Vault
            kv_client = KeyVaultClient(vault_config.url)

            # List all certificates from vault
            all_certificates = kv_client.list_certificates()

            # Apply certificate selection logic
            selection = select_certificates(
                all_certificates=all_certificates,
                include_list=vault_config.include_certificates,
                ignore_list=vault_config.ignore_certificates,
            )

            logger.info(f"  Found {selection.total_discovered} certificate(s), "
                       f"{len(selection.selected)} selected, "
                       f"{len(selection.ignored)} ignored")

            # Process selected certificates
            for cert_info in selection.selected:
                # Only include Let's Encrypt certificates
                if not is_letsencrypt_issuer(cert_info.issuer):
                    logger.debug(f"    [{cert_info.name}] Skipping - not Let's Encrypt")
                    continue

                # Compute SAN signature
                san_signature = normalize_san_signature(cert_info.domains)

                # Check if needs renewal
                needs_renewal = is_expiring_soon(cert_info.expires_on, threshold_days)

                # Create certificate record
                record = CertificateRecord(
                    vault_name=vault_config.name,
                    vault_url=vault_config.url,
                    cert_name=cert_info.name,
                    common_name=cert_info.domains[0] if cert_info.domains else "",
                    san_list=cert_info.domains,
                    san_signature=san_signature,
                    expiry_date=cert_info.expires_on,
                    thumbprint=cert_info.thumbprint,
                    needs_renewal=needs_renewal,
                    issuer=cert_info.issuer,
                )

                inventory[san_signature].append(record)

                days_remaining = format_days_remaining(cert_info.expires_on)
                status = "EXPIRING" if needs_renewal else "OK"
                logger.debug(f"    [{cert_info.name}] {status} - {days_remaining} days remaining")

        except Exception as e:
            logger.warning(f"  Failed to scan vault {vault_config.name}: {e}")
            # Continue with other vaults

    return dict(inventory)


def log_inventory_summary(
    inventory: Dict[FrozenSet[str], List[CertificateRecord]],
) -> None:
    """
    Log summary of certificate inventory with duplicate detection.

    Args:
        inventory: Certificate inventory grouped by SAN signature
    """
    logger = get_logger()

    total_certs = sum(len(group) for group in inventory.values())
    total_groups = len(inventory)
    duplicate_groups = sum(1 for group in inventory.values() if len(group) > 1)
    needs_renewal = sum(1 for group in inventory.values() if any(c.needs_renewal for c in group))

    logger.info("")
    logger.info("-" * 60)
    logger.info("INVENTORY SUMMARY")
    logger.info("-" * 60)
    logger.info(f"  Total certificates discovered: {total_certs}")
    logger.info(f"  Unique SAN groups: {total_groups}")
    logger.info(f"  Duplicate groups (same SANs across vaults): {duplicate_groups}")
    logger.info(f"  Groups needing renewal: {needs_renewal}")

    # Log duplicate groups
    if duplicate_groups > 0:
        logger.info("")
        logger.info("  Duplicate groups detected:")
        for san_sig, group in sorted(inventory.items(), key=lambda x: sorted(x[0])):
            if len(group) > 1:
                san_display = ", ".join(sorted(san_sig))
                logger.info(f"    SANs: {san_display}")
                for cert in group:
                    days = format_days_remaining(cert.expiry_date)
                    status = "EXPIRING" if cert.needs_renewal else "OK"
                    logger.info(f"      - {cert.vault_name}/{cert.cert_name} ({status}, {days} days)")

    logger.info("-" * 60)


def process_certificate_group(
    group: List[CertificateRecord],
    config: Config,
    dry_run: bool,
    pfx_password: Optional[str],
    artifact_dir: Optional[str],
    notification_manager: Optional[NotificationManager],
    use_staging: bool = False,
) -> List[RenewalResult]:
    """
    Process a group of certificates with identical SANs.

    If any certificate in the group needs renewal:
    - Renew ONCE using Certbot
    - Upload the renewed certificate to ALL vaults in the group

    Args:
        group: List of CertificateRecord with identical SANs
        config: Global configuration
        dry_run: If True, don't make actual changes
        pfx_password: Password for PFX certificate
        artifact_dir: Directory to save PFX artifacts (optional)
        notification_manager: Optional notification manager
        use_staging: If True, use Let's Encrypt staging environment

    Returns:
        List of RenewalResult for each certificate in the group
    """
    logger = get_logger()
    results: List[RenewalResult] = []

    if not group:
        return results

    # Get SAN signature for logging
    san_signature = group[0].san_signature
    san_display = ", ".join(sorted(san_signature))
    domains = group[0].san_list

    logger.info("")
    logger.info(f"Processing certificate group: {san_display}")
    logger.info(f"  Certificates in group: {len(group)}")

    # Check if any certificate needs renewal
    certs_needing_renewal = [c for c in group if c.needs_renewal]
    logger.info(f"  Certificates needing renewal: {len(certs_needing_renewal)}")

    if not certs_needing_renewal:
        logger.info(f"  Decision: SKIP (all certificates valid)")
        # Return skipped results for all
        for cert in group:
            days = format_days_remaining(cert.expiry_date)
            results.append(RenewalResult(
                vault_name=cert.vault_name,
                certificate_name=cert.cert_name,
                status=RenewalStatus.SKIPPED,
                message=f"Not expiring soon ({days} days remaining)",
                domains=cert.san_list,
            ))
        return results

    # At least one needs renewal
    trigger_cert = certs_needing_renewal[0]
    logger.info(f"  Decision: RENEW (triggered by: {trigger_cert.vault_name}/{trigger_cert.cert_name})")

    if dry_run:
        logger.info(f"  DRY RUN - would renew certificate and upload to {len(group)} vault(s)")
        for cert in group:
            results.append(RenewalResult(
                vault_name=cert.vault_name,
                certificate_name=cert.cert_name,
                status=RenewalStatus.RENEWED,
                message="Dry run - would renew",
                domains=cert.san_list,
            ))
        return results

    try:
        # Find DNS zone info
        primary_domain = domains[0] if domains else ""
        dns_zone_info = config.dns_providers.find_zone_for_domain(primary_domain)

        if not dns_zone_info:
            raise ValueError(
                f"No DNS zone configured for domain '{primary_domain}'. "
                "Add the zone to dns_providers in config.yaml"
            )

        dns_provider = dns_zone_info["provider"]
        logger.info(f"  Using {dns_provider} for zone '{dns_zone_info['zone']}'")

        # Run Certbot renewal ONCE
        logger.info(f"  Running Certbot renewal...")
        cert_paths = run_certbot_renewal(
            domains=domains,
            dns_provider=dns_provider,
            email=config.settings.letsencrypt_email,
            config=config,
            dns_zone_info=dns_zone_info,
            use_staging=use_staging,
        )

        # Convert to PFX format ONCE
        logger.info(f"  Converting to PFX format...")
        pfx_data = convert_to_pfx(
            cert_path=cert_paths["cert"],
            key_path=cert_paths["privkey"],
            chain_path=cert_paths["chain"],
            password=pfx_password,
        )

        # Get new expiry date for notifications
        new_expiry_date = get_certificate_expiry(cert_paths["cert"])

        # Save artifact ONCE (using first certificate's naming)
        if artifact_dir:
            artifact_path = save_pfx_artifact(
                pfx_data=pfx_data,
                artifact_dir=artifact_dir,
                vault_name=trigger_cert.vault_name,
                cert_name=trigger_cert.cert_name,
            )
            logger.info(f"  Saved artifact: {artifact_path}")

        # Upload to ALL vaults in the group
        logger.info(f"  Uploading to {len(group)} vault(s):")
        for cert in group:
            try:
                kv_client = KeyVaultClient(cert.vault_url)
                upload_certificate(
                    client=kv_client,
                    cert_name=cert.cert_name,
                    pfx_data=pfx_data,
                    password=pfx_password,
                )

                filename = generate_certificate_filename(cert.vault_name, cert.cert_name)
                logger.info(f"    - {cert.vault_name}/{cert.cert_name} → {filename} SUCCESS")

                # Save artifact for each vault (with vault-specific naming)
                if artifact_dir:
                    vault_artifact_path = save_pfx_artifact(
                        pfx_data=pfx_data,
                        artifact_dir=artifact_dir,
                        vault_name=cert.vault_name,
                        cert_name=cert.cert_name,
                    )
                    logger.debug(f"      Artifact: {vault_artifact_path}")

                # Send success notification
                if notification_manager and notification_manager.is_enabled():
                    _send_certificate_notification(
                        notification_manager=notification_manager,
                        vault_name=cert.vault_name,
                        cert_name=cert.cert_name,
                        domains=cert.san_list,
                        expiry_date=new_expiry_date,
                        status="SUCCESS",
                    )

                results.append(RenewalResult(
                    vault_name=cert.vault_name,
                    certificate_name=cert.cert_name,
                    status=RenewalStatus.RENEWED,
                    message="Successfully renewed",
                    domains=cert.san_list,
                ))

            except Exception as upload_error:
                error_msg = str(upload_error)
                logger.error(f"    - {cert.vault_name}/{cert.cert_name} FAILED: {error_msg}")

                # Send failure notification
                if notification_manager and notification_manager.is_enabled():
                    _send_certificate_notification(
                        notification_manager=notification_manager,
                        vault_name=cert.vault_name,
                        cert_name=cert.cert_name,
                        domains=cert.san_list,
                        expiry_date=cert.expiry_date,
                        status="FAILED",
                        failure_reason=f"Upload failed: {error_msg}",
                    )

                results.append(RenewalResult(
                    vault_name=cert.vault_name,
                    certificate_name=cert.cert_name,
                    status=RenewalStatus.FAILED,
                    message=f"Upload failed: {error_msg}",
                    domains=cert.san_list,
                ))

    except Exception as e:
        error_msg = str(e)
        logger.error(f"  Renewal failed: {error_msg}")

        # Mark all certificates in group as failed
        for cert in group:
            if notification_manager and notification_manager.is_enabled():
                _send_certificate_notification(
                    notification_manager=notification_manager,
                    vault_name=cert.vault_name,
                    cert_name=cert.cert_name,
                    domains=cert.san_list,
                    expiry_date=cert.expiry_date,
                    status="FAILED",
                    failure_reason=error_msg,
                )

            results.append(RenewalResult(
                vault_name=cert.vault_name,
                certificate_name=cert.cert_name,
                status=RenewalStatus.FAILED,
                message=error_msg,
                domains=cert.san_list,
            ))

    return results


def _send_certificate_notification(
    notification_manager: NotificationManager,
    vault_name: str,
    cert_name: str,
    domains: List[str],
    expiry_date: Optional[datetime],
    status: str,
    failure_reason: Optional[str] = None,
) -> None:
    """
    Send notification for a certificate event.

    This is a non-blocking helper that logs but doesn't raise on failure.

    Args:
        notification_manager: Notification manager instance
        vault_name: Name of the Key Vault
        cert_name: Name of the certificate
        domains: List of domains (first is CN, rest are SANs)
        expiry_date: Certificate expiry date
        status: Notification status ("SUCCESS" or "FAILED")
        failure_reason: Reason for failure (if status is FAILED)
    """
    # Extract CN from domains list
    common_name = domains[0] if domains else "Unknown"

    context = NotificationContext(
        vault_name=vault_name,
        certificate_name=cert_name,
        common_name=common_name,
        san_list=domains if domains else [],
        expiry_date=expiry_date,
        status=status,
        failure_reason=failure_reason,
    )

    notification_manager.notify(context)


def process_certificate(
    kv_client: KeyVaultClient,
    cert_info: CertificateInfo,
    vault_config: VaultConfig,
    config: Config,
    dry_run: bool = False,
    pfx_password: Optional[str] = None,
    notification_manager: Optional[NotificationManager] = None,
    use_staging: bool = False,
) -> RenewalResult:
    """
    Process a single certificate for potential renewal.

    Args:
        kv_client: Key Vault client instance
        cert_info: Certificate information
        vault_config: Vault configuration
        config: Global configuration
        dry_run: If True, don't make actual changes
        pfx_password: Password for PFX certificate
        notification_manager: Optional notification manager for sending alerts
        use_staging: If True, use Let's Encrypt staging environment

    Returns:
        RenewalResult with status and details
    """
    logger = get_logger()
    cert_name = cert_info.name
    vault_name = vault_config.name

    # Note: ignore_certificates and include_certificates filtering is handled
    # by select_certificates() in process_vault() before this function is called.

    # Check if issuer is Let's Encrypt
    if not is_letsencrypt_issuer(cert_info.issuer):
        logger.info(
            f"  [{cert_name}] Skipping - not Let's Encrypt "
            f"(issuer: {cert_info.issuer})"
        )
        return RenewalResult(
            vault_name=vault_name,
            certificate_name=cert_name,
            status=RenewalStatus.SKIPPED,
            message=f"Not a Let's Encrypt certificate (issuer: {cert_info.issuer})",
        )

    # Check expiration
    days_remaining = format_days_remaining(cert_info.expires_on)
    if not is_expiring_soon(cert_info.expires_on, config.settings.expiration_threshold_days):
        logger.debug(
            f"  [{cert_name}] OK - {days_remaining} days remaining"
        )
        return RenewalResult(
            vault_name=vault_name,
            certificate_name=cert_name,
            status=RenewalStatus.SKIPPED,
            message=f"Not expiring soon ({days_remaining} days remaining)",
        )

    # Certificate needs renewal
    logger.warning(
        f"  [{cert_name}] EXPIRING in {days_remaining} days - renewal needed"
    )

    if dry_run:
        logger.info(f"  [{cert_name}] DRY RUN - would renew certificate")
        return RenewalResult(
            vault_name=vault_name,
            certificate_name=cert_name,
            status=RenewalStatus.RENEWED,
            message="Dry run - would renew",
            domains=cert_info.domains,
        )

    try:
        # Find DNS zone info (auto-detect provider from domain)
        primary_domain = cert_info.domains[0] if cert_info.domains else ""
        dns_zone_info = config.dns_providers.find_zone_for_domain(primary_domain)

        if not dns_zone_info:
            raise ValueError(
                f"No DNS zone configured for domain '{primary_domain}'. "
                "Add the zone to dns_providers in config.yaml"
            )

        dns_provider = dns_zone_info["provider"]
        logger.info(
            f"  [{cert_name}] Using {dns_provider} for zone '{dns_zone_info['zone']}'"
        )

        # Run Certbot renewal
        logger.info(f"  [{cert_name}] Running Certbot renewal...")
        cert_paths = run_certbot_renewal(
            domains=cert_info.domains,
            dns_provider=dns_provider,
            email=config.settings.letsencrypt_email,
            config=config,
            dns_zone_info=dns_zone_info,
            use_staging=use_staging,
        )

        # Convert to PFX format
        logger.info(f"  [{cert_name}] Converting to PFX format...")
        pfx_data = convert_to_pfx(
            cert_path=cert_paths["cert"],
            key_path=cert_paths["privkey"],
            chain_path=cert_paths["chain"],
            password=pfx_password,
        )

        # Upload to Key Vault
        logger.info(f"  [{cert_name}] Uploading to Key Vault...")
        upload_certificate(
            client=kv_client,
            cert_name=cert_name,
            pfx_data=pfx_data,
            password=pfx_password,
        )

        logger.info(f"  [{cert_name}] Successfully renewed and uploaded")

        # Send success notification with new certificate expiry date
        if notification_manager and notification_manager.is_enabled():
            new_expiry_date = get_certificate_expiry(cert_paths["cert"])
            _send_certificate_notification(
                notification_manager=notification_manager,
                vault_name=vault_name,
                cert_name=cert_name,
                domains=cert_info.domains,
                expiry_date=new_expiry_date,
                status="SUCCESS",
            )

        return RenewalResult(
            vault_name=vault_name,
            certificate_name=cert_name,
            status=RenewalStatus.RENEWED,
            message="Successfully renewed",
            domains=cert_info.domains,
        )

    except Exception as e:
        error_msg = str(e)
        logger.error(f"  [{cert_name}] Renewal failed: {error_msg}")

        # Send failure notification
        if notification_manager and notification_manager.is_enabled():
            _send_certificate_notification(
                notification_manager=notification_manager,
                vault_name=vault_name,
                cert_name=cert_name,
                domains=cert_info.domains,
                expiry_date=cert_info.expires_on,
                status="FAILED",
                failure_reason=error_msg,
            )

        return RenewalResult(
            vault_name=vault_name,
            certificate_name=cert_name,
            status=RenewalStatus.FAILED,
            message=error_msg,
            domains=cert_info.domains,
        )


def _log_certificate_selection(
    vault_name: str,
    selection_result,
    include_list: List[str],
    ignore_list: List[str],
) -> None:
    """
    Log detailed certificate selection information.

    Args:
        vault_name: Name of the vault being processed
        selection_result: Result from select_certificates()
        include_list: Configured include_certificates list
        ignore_list: Configured ignore_certificates list
    """
    logger = get_logger()

    # Log discovery summary
    logger.info(f"  Found {selection_result.total_discovered} certificate(s)")

    # Log selection mode
    if include_list:
        logger.info(f"  Selection mode: include_certificates ({len(include_list)} configured)")
    else:
        logger.info("  Selection mode: all certificates (no include_certificates filter)")

    # Log selection results summary
    selected_count = len(selection_result.selected)
    ignored_count = len(selection_result.ignored)
    excluded_count = len(selection_result.excluded)

    logger.info(
        f"  Selection result: {selected_count} selected, "
        f"{ignored_count} ignored, {excluded_count} excluded"
    )

    # Log detailed per-certificate info at debug level
    for sel in selection_result.selections:
        if sel.reason == SelectionReason.IGNORED:
            logger.debug(f"    [{sel.name}] IGNORED - in ignore_certificates list")
        elif sel.reason == SelectionReason.NOT_IN_INCLUDE_LIST:
            logger.debug(f"    [{sel.name}] EXCLUDED - not in include_certificates list")
        elif sel.selected:
            logger.debug(f"    [{sel.name}] SELECTED - will be processed")

    # Log ignored certificates at info level if any
    if selection_result.ignored:
        logger.info(f"  Ignored certificates: {', '.join(selection_result.ignored)}")

    # Log excluded certificates at debug level if any
    if selection_result.excluded:
        logger.debug(f"  Excluded certificates (not in include_list): {', '.join(selection_result.excluded)}")


def process_vault(
    vault_config: VaultConfig,
    config: Config,
    dry_run: bool = False,
    pfx_password: Optional[str] = None,
    notification_manager: Optional[NotificationManager] = None,
    use_staging: bool = False,
) -> VaultSummary:
    """
    Process certificates in a vault based on include/ignore configuration.

    Certificate selection rules (in order of precedence):
    1. ignore_certificates: ALWAYS takes precedence - these are NEVER processed
    2. include_certificates empty: Process ALL certificates (minus ignored)
    3. include_certificates specified: ONLY process these (minus ignored)

    Args:
        vault_config: Vault configuration with include/ignore lists
        config: Global configuration
        dry_run: If True, don't make actual changes
        pfx_password: Password for PFX certificate
        notification_manager: Optional notification manager for sending alerts
        use_staging: If True, use Let's Encrypt staging environment

    Returns:
        VaultSummary with all processing results and statistics
    """
    logger = get_logger()

    # Initialize vault summary
    vault_summary = VaultSummary(
        name=vault_config.name,
        url=vault_config.url,
    )

    logger.info(f"\nProcessing vault: {vault_config.name}")
    logger.info(f"  URL: {vault_config.url}")

    try:
        # Connect to Key Vault
        kv_client = KeyVaultClient(vault_config.url)

        # List all certificates from vault
        all_certificates = kv_client.list_certificates()

        # Apply certificate selection logic
        selection = select_certificates(
            all_certificates=all_certificates,
            include_list=vault_config.include_certificates,
            ignore_list=vault_config.ignore_certificates,
        )

        # Update vault summary with selection stats
        vault_summary.certificates_discovered = selection.total_discovered
        vault_summary.certificates_selected = len(selection.selected)
        vault_summary.certificates_ignored = len(selection.ignored)
        vault_summary.certificates_excluded = len(selection.excluded)

        # Log selection details
        _log_certificate_selection(
            vault_name=vault_config.name,
            selection_result=selection,
            include_list=vault_config.include_certificates,
            ignore_list=vault_config.ignore_certificates,
        )

        # Add IGNORED results for certificates in ignore list
        for ignored_name in selection.ignored:
            vault_summary.results.append(RenewalResult(
                vault_name=vault_config.name,
                certificate_name=ignored_name,
                status=RenewalStatus.IGNORED,
                message="Certificate in ignore_certificates list",
            ))

        # Process only selected certificates
        for cert_info in selection.selected:
            result = process_certificate(
                kv_client=kv_client,
                cert_info=cert_info,
                vault_config=vault_config,
                config=config,
                dry_run=dry_run,
                pfx_password=pfx_password,
                notification_manager=notification_manager,
                use_staging=use_staging,
            )
            vault_summary.results.append(result)

            # Update counts
            if result.status == RenewalStatus.RENEWED:
                vault_summary.renewed += 1
            elif result.status == RenewalStatus.SKIPPED:
                vault_summary.skipped += 1
            elif result.status == RenewalStatus.FAILED:
                vault_summary.failed += 1

            # Stop on error if not continuing on error
            if result.status == RenewalStatus.FAILED and not config.settings.continue_on_error:
                logger.error("Stopping due to error (continue_on_error=false)")
                break

    except Exception as e:
        error_msg = str(e)
        logger.error(f"  Failed to process vault: {error_msg}")
        vault_summary.error = error_msg
        vault_summary.failed += 1
        vault_summary.results.append(RenewalResult(
            vault_name=vault_config.name,
            certificate_name="*",
            status=RenewalStatus.FAILED,
            message=f"Vault access failed: {error_msg}",
        ))

    return vault_summary


def process_single_certificate(
    vault_name: str,
    certificate_name: str,
    config: Config,
    dry_run: bool = False,
    pfx_password: Optional[str] = None,
    notification_manager: Optional[NotificationManager] = None,
    use_staging: bool = False,
) -> RenewalResult:
    """
    Process a single certificate in manual mode.

    Args:
        vault_name: Name of the Key Vault
        certificate_name: Name of the certificate
        config: Global configuration
        dry_run: If True, don't make actual changes
        pfx_password: Password for PFX certificate
        notification_manager: Optional notification manager for sending alerts
        use_staging: If True, use Let's Encrypt staging environment

    Returns:
        RenewalResult with status and details
    """
    logger = get_logger()

    # Find vault in config or create temporary config
    vault_config = None
    for vc in config.vaults:
        if vc.name == vault_name:
            vault_config = vc
            break

    if not vault_config:
        # Create temporary vault config
        vault_config = VaultConfig(
            name=vault_name,
            url=f"https://{vault_name}.vault.azure.net/",
            ignore_certificates=[],
        )

    logger.info(f"\nManual renewal for: {vault_name}/{certificate_name}")

    try:
        # Connect to Key Vault
        kv_client = KeyVaultClient(vault_config.url)

        # Get certificate details
        cert_info = get_certificate_details(kv_client, certificate_name)

        if not cert_info:
            return RenewalResult(
                vault_name=vault_name,
                certificate_name=certificate_name,
                status=RenewalStatus.FAILED,
                message="Certificate not found",
            )

        return process_certificate(
            kv_client=kv_client,
            cert_info=cert_info,
            vault_config=vault_config,
            config=config,
            dry_run=dry_run,
            pfx_password=pfx_password,
            notification_manager=notification_manager,
            use_staging=use_staging,
        )

    except Exception as e:
        logger.error(f"Failed to process certificate: {e}")
        return RenewalResult(
            vault_name=vault_name,
            certificate_name=certificate_name,
            status=RenewalStatus.FAILED,
            message=str(e),
        )


def create_certificate(
    domains: List[str],
    cert_name: str,
    vault_url: str,
    subscription_id: str,
    config: Config,
    dry_run: bool = False,
    pfx_password: Optional[str] = None,
    notification_manager: Optional[NotificationManager] = None,
    use_staging: bool = False,
) -> RenewalResult:
    """
    Create a new certificate and upload to Key Vault.

    Args:
        domains: List of domain names (SANs) for the certificate
        cert_name: Name for the certificate in Key Vault
        vault_url: URL of the target Key Vault
        subscription_id: Azure subscription ID for the Key Vault
        config: Global configuration
        dry_run: If True, don't make actual changes
        pfx_password: Password for PFX certificate
        notification_manager: Optional notification manager for sending alerts
        use_staging: If True, use Let's Encrypt staging environment

    Returns:
        RenewalResult with status and details
    """
    logger = get_logger()
    vault_name = vault_url.split("//")[1].split(".")[0]

    logger.info(f"\nCreating new certificate: {cert_name}")
    logger.info(f"  Domains: {', '.join(domains)}")
    logger.info(f"  Vault: {vault_name}")

    if dry_run:
        logger.info(f"  DRY RUN - would create certificate and upload to Key Vault")
        return RenewalResult(
            vault_name=vault_name,
            certificate_name=cert_name,
            status=RenewalStatus.RENEWED,
            message="Dry run - would create certificate",
            domains=domains,
        )

    try:
        # Find DNS zone info for the primary domain
        primary_domain = domains[0]
        dns_zone_info = config.dns_providers.find_zone_for_domain(primary_domain)

        if not dns_zone_info:
            raise ValueError(
                f"No DNS zone configured for domain '{primary_domain}'. "
                "Add the zone to dns_providers in config.yaml"
            )

        dns_provider = dns_zone_info["provider"]
        logger.info(f"  Using {dns_provider} for zone '{dns_zone_info['zone']}'")

        # Run Certbot to create new certificate
        logger.info(f"  Running Certbot to create certificate...")
        cert_paths = run_certbot_create(
            domains=domains,
            dns_provider=dns_provider,
            email=config.settings.letsencrypt_email,
            config=config,
            dns_zone_info=dns_zone_info,
            use_staging=use_staging,
        )

        # Convert to PFX format
        logger.info(f"  Converting to PFX format...")
        pfx_data = convert_to_pfx(
            cert_path=cert_paths["cert"],
            key_path=cert_paths["privkey"],
            chain_path=cert_paths["chain"],
            password=pfx_password,
        )

        # Upload to Key Vault
        logger.info(f"  Uploading to Key Vault...")
        kv_client = KeyVaultClient(vault_url)
        upload_certificate(
            client=kv_client,
            cert_name=cert_name,
            pfx_data=pfx_data,
            password=pfx_password,
        )

        logger.info(f"  Successfully created and uploaded certificate: {cert_name}")

        # Send success notification with new certificate expiry date
        if notification_manager and notification_manager.is_enabled():
            new_expiry_date = get_certificate_expiry(cert_paths["cert"])
            _send_certificate_notification(
                notification_manager=notification_manager,
                vault_name=vault_name,
                cert_name=cert_name,
                domains=domains,
                expiry_date=new_expiry_date,
                status="SUCCESS",
            )

        return RenewalResult(
            vault_name=vault_name,
            certificate_name=cert_name,
            status=RenewalStatus.RENEWED,
            message="Successfully created",
            domains=domains,
        )

    except Exception as e:
        error_msg = str(e)
        logger.error(f"  Certificate creation failed: {error_msg}")

        # Send failure notification
        if notification_manager and notification_manager.is_enabled():
            _send_certificate_notification(
                notification_manager=notification_manager,
                vault_name=vault_name,
                cert_name=cert_name,
                domains=domains,
                expiry_date=None,
                status="FAILED",
                failure_reason=error_msg,
            )

        return RenewalResult(
            vault_name=vault_name,
            certificate_name=cert_name,
            status=RenewalStatus.FAILED,
            message=str(e),
            domains=domains,
        )


def print_execution_summary(
    summary: ExecutionSummary,
    output_json: bool = False,
) -> None:
    """
    Print a comprehensive execution summary.

    This produces a visually separated summary block at the end of execution
    containing per-vault details and global statistics.

    Args:
        summary: ExecutionSummary with all results
        output_json: If True, also output machine-readable JSON
    """
    logger = get_logger()

    # Visual separator for easy log parsing
    separator = "=" * 70

    logger.info("")
    logger.info(separator)
    logger.info("EXECUTION SUMMARY")
    logger.info(separator)
    logger.info("")

    # Overall status
    status_str = "SUCCESS" if summary.success else "FAILED"
    if summary.dry_run:
        status_str += " (DRY RUN)"
    if summary.use_staging:
        status_str += " (STAGING)"

    # Let's Encrypt environment
    le_env = "STAGING" if summary.use_staging else "PRODUCTION"

    logger.info(f"Status: {status_str}")
    logger.info(f"Task: {summary.task}")
    logger.info(f"Let's Encrypt Environment: {le_env}")
    logger.info(f"Started: {summary.started_at}")
    logger.info(f"Completed: {summary.completed_at}")
    logger.info("")

    # Global statistics
    logger.info("-" * 40)
    logger.info("GLOBAL STATISTICS")
    logger.info("-" * 40)
    logger.info(f"  Total vaults scanned:        {summary.total_vaults}")
    logger.info(f"  Total certificates evaluated: {summary.total_certificates_evaluated}")
    logger.info(f"  Renewed successfully:         {summary.total_renewed}")
    logger.info(f"  Skipped (not expiring):       {summary.total_skipped}")
    logger.info(f"  Ignored (in ignore list):     {summary.total_ignored}")
    logger.info(f"  Failed:                       {summary.total_failed}")
    logger.info("")

    # Per-vault details
    if summary.vaults:
        logger.info("-" * 40)
        logger.info("PER-VAULT DETAILS")
        logger.info("-" * 40)

        for vault in summary.vaults:
            # Vault header
            vault_status = "ERROR" if vault.has_failures else "OK"
            logger.info(f"\n  [{vault_status}] {vault.name}")

            if vault.error:
                logger.error(f"      Vault Error: {vault.error}")

            if vault.certificates_discovered > 0:
                logger.info(f"      Discovered: {vault.certificates_discovered}, "
                          f"Selected: {vault.certificates_selected}, "
                          f"Ignored: {vault.certificates_ignored}")

            # Certificate details
            for result in vault.results:
                status_icon = {
                    RenewalStatus.RENEWED: "SUCCESS",
                    RenewalStatus.SKIPPED: "SKIPPED",
                    RenewalStatus.IGNORED: "IGNORED",
                    RenewalStatus.FAILED: "FAILED",
                }.get(result.status, "UNKNOWN")

                if result.status == RenewalStatus.FAILED:
                    logger.error(f"      [{status_icon}] {result.certificate_name}: {result.message}")
                elif result.status == RenewalStatus.RENEWED:
                    logger.info(f"      [{status_icon}] {result.certificate_name}")
                else:
                    logger.info(f"      [{status_icon}] {result.certificate_name}: {result.message}")

    # Global errors (outside vault processing)
    if summary.global_errors:
        logger.info("")
        logger.error("-" * 40)
        logger.error("GLOBAL ERRORS")
        logger.error("-" * 40)
        for error in summary.global_errors:
            logger.error(f"  - {error}")

    # Failed certificates summary (easy to spot)
    failed_certs = []
    for vault in summary.vaults:
        for result in vault.results:
            if result.status == RenewalStatus.FAILED:
                failed_certs.append(f"{vault.name}/{result.certificate_name}")

    if failed_certs:
        logger.info("")
        logger.error("-" * 40)
        logger.error("FAILED CERTIFICATES")
        logger.error("-" * 40)
        for cert in failed_certs:
            logger.error(f"  - {cert}")

    # Renewed certificates summary
    renewed_certs = []
    for vault in summary.vaults:
        for result in vault.results:
            if result.status == RenewalStatus.RENEWED:
                renewed_certs.append(f"{vault.name}/{result.certificate_name}")

    if renewed_certs:
        logger.info("")
        logger.info("-" * 40)
        logger.info("RENEWED CERTIFICATES")
        logger.info("-" * 40)
        for cert in renewed_certs:
            logger.info(f"  - {cert}")

    # Final status and exit code
    logger.info("")
    logger.info(separator)
    logger.info(f"Exit Code: {summary.exit_code}")
    logger.info(separator)

    # Output status line for CI/CD pipeline parsing
    # This line can be captured by GitHub Actions using grep or output parsing
    if summary.success:
        print("PIPELINE_STATUS=SUCCESS")
    else:
        print("PIPELINE_STATUS=FAILURE")

    # Optional JSON output for machine parsing
    if output_json:
        logger.info("")
        logger.info("--- BEGIN JSON SUMMARY ---")
        print(summary.to_json())
        logger.info("--- END JSON SUMMARY ---")


def _create_notification_manager(config: Config) -> NotificationManager:
    """
    Create and configure the notification manager from config.

    Args:
        config: Application configuration

    Returns:
        Configured NotificationManager instance
    """
    return NotificationManager(config.notifications)


def main() -> int:
    """
    Main entry point.

    Handles all execution modes (create, renew, auto) and produces a comprehensive
    execution summary with proper exit codes for CI/CD integration.

    Exit Codes:
        0 - All operations succeeded
        1 - One or more operations failed
        2 - Configuration error

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    # Parse arguments
    args = parse_arguments()

    # Setup logging
    logger = setup_logger(
        verbose=args.verbose,
        use_colors=not args.no_color,
    )

    logger.info("Azure Key Vault Certificate Renewal Automation")
    logger.info("=" * 50)

    if args.dry_run:
        logger.warning("DRY RUN MODE - No changes will be made")

    # Log Let's Encrypt environment mode
    if args.use_staging:
        logger.warning("STAGING MODE - Using Let's Encrypt staging environment")
        logger.warning("Certificates issued will NOT be trusted by browsers")
    else:
        logger.info("Using Let's Encrypt production environment")

    # Set AWS region from command line argument (highest priority)
    if args.aws_region:
        os.environ["AWS_DEFAULT_REGION"] = args.aws_region
        logger.info(f"AWS region set to: {args.aws_region}")

    # Determine task type for summary
    if args.task == "create":
        task_type = "create"
    elif args.auto:
        task_type = "renew-auto"
    else:
        task_type = "renew-single"

    # Initialize execution summary
    summary = ExecutionSummary(
        task=task_type,
        dry_run=args.dry_run,
        use_staging=args.use_staging,
    )

    try:
        # Load configuration
        config = load_config(args.config)

        # Apply command-line overrides
        if args.threshold:
            config.settings.expiration_threshold_days = args.threshold
            logger.info(f"Expiration threshold overridden to {args.threshold} days")

        if args.dry_run:
            config.settings.dry_run = True

        # Apply key type overrides from CLI
        if args.key_type:
            config.settings.key_type = args.key_type.lower()
            logger.info(f"Key type overridden to: {args.key_type}")
        if args.rsa_key_size:
            config.settings.rsa_key_size = args.rsa_key_size
            logger.info(f"RSA key size overridden to: {args.rsa_key_size}")
        if args.elliptic_curve:
            config.settings.elliptic_curve = args.elliptic_curve.lower()
            logger.info(f"Elliptic curve overridden to: {args.elliptic_curve}")

        # Get PFX password (command-line > env var > empty)
        pfx_password = get_pfx_password(args.pfx_password)
        if pfx_password:
            logger.info("PFX password configured")

        # Initialize notification manager
        notification_manager = _create_notification_manager(config)
        if notification_manager.is_enabled():
            logger.info("Notifications enabled")

        # Process based on task/mode
        if args.task == "create":
            # Create mode - create new certificate and upload to Key Vault
            domains = [d.strip() for d in args.san.split(",")]
            vault_name = args.vault_url.split("//")[1].split(".")[0]

            result = create_certificate(
                domains=domains,
                cert_name=args.certificate_name,
                vault_url=args.vault_url,
                subscription_id=args.subscription,
                config=config,
                dry_run=args.dry_run,
                pfx_password=pfx_password,
                notification_manager=notification_manager,
                use_staging=args.use_staging,
            )

            # Create vault summary for create task
            vault_summary = VaultSummary(
                name=vault_name,
                url=args.vault_url,
                certificates_discovered=1,
                certificates_selected=1,
            )
            vault_summary.results.append(result)

            if result.status == RenewalStatus.RENEWED:
                vault_summary.renewed = 1
            elif result.status == RenewalStatus.FAILED:
                vault_summary.failed = 1

            summary.add_vault_summary(vault_summary)

        elif args.auto:
            # Automatic mode - use inventory-based processing with duplicate detection
            logger.info(f"\nScanning {len(config.vaults)} vault(s) for certificates...")

            # Phase 1: Build global certificate inventory
            inventory = build_certificate_inventory(
                config=config,
                threshold_days=config.settings.expiration_threshold_days,
            )

            # Log inventory summary
            log_inventory_summary(inventory)

            # Phase 2: Process each certificate group
            logger.info("")
            logger.info("=" * 60)
            logger.info("PHASE 2: Processing Certificate Groups")
            logger.info("=" * 60)

            # Track per-vault summaries for reporting
            vault_summaries: Dict[str, VaultSummary] = {}

            # Process groups in deterministic order (sorted by SAN signature)
            groups_processed = 0
            groups_renewed = 0

            for san_signature in sorted(inventory.keys(), key=lambda x: sorted(x)):
                group = inventory[san_signature]
                groups_processed += 1

                # Process the group
                results = process_certificate_group(
                    group=group,
                    config=config,
                    dry_run=args.dry_run,
                    pfx_password=pfx_password,
                    artifact_dir=args.artifact_dir,
                    notification_manager=notification_manager,
                    use_staging=args.use_staging,
                )

                # Track if this group was renewed
                if any(r.status == RenewalStatus.RENEWED for r in results):
                    groups_renewed += 1

                # Aggregate results into per-vault summaries
                for result in results:
                    vault_name = result.vault_name

                    if vault_name not in vault_summaries:
                        # Find vault URL
                        vault_url = ""
                        for vc in config.vaults:
                            if vc.name == vault_name:
                                vault_url = vc.url
                                break

                        vault_summaries[vault_name] = VaultSummary(
                            name=vault_name,
                            url=vault_url,
                        )

                    vs = vault_summaries[vault_name]
                    vs.results.append(result)
                    vs.certificates_discovered += 1
                    vs.certificates_selected += 1

                    if result.status == RenewalStatus.RENEWED:
                        vs.renewed += 1
                    elif result.status == RenewalStatus.SKIPPED:
                        vs.skipped += 1
                    elif result.status == RenewalStatus.FAILED:
                        vs.failed += 1

            # Add all vault summaries to execution summary
            for vs in vault_summaries.values():
                summary.add_vault_summary(vs)

            # Log final summary
            logger.info("")
            logger.info("=" * 60)
            logger.info("RENEWAL SUMMARY")
            logger.info("=" * 60)
            logger.info(f"  Total SAN groups processed: {groups_processed}")
            logger.info(f"  Groups renewed: {groups_renewed}")
            logger.info(f"  Certificates updated: {summary.total_renewed}")
            logger.info(f"  Vaults affected: {len(vault_summaries)}")

        else:
            # Manual mode - process single certificate
            result = process_single_certificate(
                vault_name=args.vault_name,
                certificate_name=args.certificate_name,
                config=config,
                dry_run=args.dry_run,
                pfx_password=pfx_password,
                notification_manager=notification_manager,
                use_staging=args.use_staging,
            )

            # Find vault URL from config
            vault_url = ""
            for vc in config.vaults:
                if vc.name == args.vault_name:
                    vault_url = vc.url
                    break

            # Create vault summary for single cert mode
            vault_summary = VaultSummary(
                name=args.vault_name,
                url=vault_url,
                certificates_discovered=1,
                certificates_selected=1,
            )
            vault_summary.results.append(result)

            if result.status == RenewalStatus.RENEWED:
                vault_summary.renewed = 1
            elif result.status == RenewalStatus.SKIPPED:
                vault_summary.skipped = 1
            elif result.status == RenewalStatus.FAILED:
                vault_summary.failed = 1

            summary.add_vault_summary(vault_summary)

    except ConfigurationError as e:
        error_msg = f"Configuration error: {e}"
        logger.error(error_msg)
        summary.add_global_error(error_msg)
        summary.exit_code = 2

    except Exception as e:
        error_msg = f"Fatal error: {e}"
        logger.error(error_msg)
        summary.add_global_error(error_msg)
        if args.verbose:
            import traceback
            traceback.print_exc()

    # Finalize and print summary
    summary.finalize()
    print_execution_summary(summary, output_json=args.json_summary)

    return summary.exit_code


if __name__ == "__main__":
    sys.exit(main())
