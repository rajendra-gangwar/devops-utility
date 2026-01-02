"""
Common utility functions.

Provides helper functions for date calculations, certificate validation,
and other common operations.
"""

import os
import re
from datetime import datetime, timezone, timedelta
from typing import Optional, Union, List, Tuple, Any, FrozenSet
from dataclasses import dataclass
from enum import Enum


def is_expiring_soon(
    expires_on: Optional[datetime],
    threshold_days: int = 10,
) -> bool:
    """
    Check if a certificate is expiring within the threshold.

    Args:
        expires_on: Certificate expiration datetime (should be timezone-aware)
        threshold_days: Number of days before expiration to consider "soon"

    Returns:
        True if certificate is expired or expiring within threshold
    """
    if expires_on is None:
        return False

    # Ensure timezone-aware
    if expires_on.tzinfo is None:
        expires_on = expires_on.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    threshold = now + timedelta(days=threshold_days)

    return expires_on <= threshold


def format_days_remaining(
    expires_on: Optional[datetime],
) -> Union[int, str]:
    """
    Calculate days remaining until expiration.

    Args:
        expires_on: Certificate expiration datetime

    Returns:
        Number of days remaining (negative if expired), or "unknown"
    """
    if expires_on is None:
        return "unknown"

    # Ensure timezone-aware
    if expires_on.tzinfo is None:
        expires_on = expires_on.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    delta = expires_on - now

    return delta.days


def is_letsencrypt_issuer(issuer: Optional[str]) -> bool:
    """
    Check if the certificate issuer is Let's Encrypt.

    Args:
        issuer: Certificate issuer organization name

    Returns:
        True if issuer appears to be Let's Encrypt
    """
    if issuer is None:
        return False

    issuer_lower = issuer.lower()

    # Known Let's Encrypt issuer patterns
    letsencrypt_patterns = [
        "let's encrypt",
        "letsencrypt",
        "lets encrypt",
        "isrg",  # Internet Security Research Group
        "r3",    # Let's Encrypt intermediate
        "r4",    # Let's Encrypt intermediate
        "e1",    # Let's Encrypt ECDSA intermediate
        "e2",    # Let's Encrypt ECDSA intermediate
    ]

    for pattern in letsencrypt_patterns:
        if pattern in issuer_lower:
            return True

    return False


def sanitize_cert_name(name: str) -> str:
    """
    Sanitize a certificate name for use in Key Vault.

    Azure Key Vault certificate names must:
    - Be 1-127 characters
    - Contain only alphanumeric characters and hyphens
    - Start with a letter
    - Not end with a hyphen

    Args:
        name: Original certificate name

    Returns:
        Sanitized certificate name
    """
    # Replace invalid characters with hyphens
    sanitized = re.sub(r"[^a-zA-Z0-9-]", "-", name)

    # Remove consecutive hyphens
    sanitized = re.sub(r"-+", "-", sanitized)

    # Ensure starts with letter
    if sanitized and not sanitized[0].isalpha():
        sanitized = "cert-" + sanitized

    # Remove trailing hyphens
    sanitized = sanitized.rstrip("-")

    # Truncate to max length
    sanitized = sanitized[:127]

    return sanitized


def format_expiration_status(
    expires_on: Optional[datetime],
    threshold_days: int = 10,
) -> str:
    """
    Format a human-readable expiration status.

    Args:
        expires_on: Certificate expiration datetime
        threshold_days: Days threshold for "expiring" status

    Returns:
        Formatted status string
    """
    if expires_on is None:
        return "Unknown expiration"

    days = format_days_remaining(expires_on)

    if isinstance(days, str):
        return "Unknown expiration"

    if days < 0:
        return f"EXPIRED ({abs(days)} days ago)"
    elif days == 0:
        return "EXPIRES TODAY"
    elif days <= threshold_days:
        return f"EXPIRING in {days} day{'s' if days != 1 else ''}"
    else:
        return f"Valid ({days} days remaining)"


def get_primary_domain(domains: list) -> Optional[str]:
    """
    Get the primary domain from a list of domains.

    The primary domain is the first non-wildcard domain,
    or the first domain if all are wildcards.

    Args:
        domains: List of domain names

    Returns:
        Primary domain or None if list is empty
    """
    if not domains:
        return None

    # Prefer non-wildcard domains
    for domain in domains:
        if not domain.startswith("*."):
            return domain

    # Fall back to first domain (removing wildcard prefix)
    return domains[0].replace("*.", "")


class SelectionReason(Enum):
    """Reason why a certificate was selected or excluded."""
    INCLUDED = "included"           # In include_list (or include_list empty)
    IGNORED = "ignored"             # In ignore_list
    NOT_IN_INCLUDE_LIST = "not_in_include_list"  # Not in non-empty include_list


@dataclass
class CertificateSelection:
    """Result of certificate selection for a single certificate."""
    name: str
    selected: bool
    reason: SelectionReason


@dataclass
class SelectionResult:
    """Complete result of certificate selection for a vault."""
    selected: List[Any]          # Certificates selected for processing
    ignored: List[str]           # Certificate names that were ignored
    excluded: List[str]          # Certificate names not in include_list
    total_discovered: int        # Total certificates found in vault
    selections: List[CertificateSelection]  # Detailed selection info for each cert


def select_certificates(
    all_certificates: List[Any],
    include_list: Optional[List[str]] = None,
    ignore_list: Optional[List[str]] = None,
    name_extractor: Optional[callable] = None,
) -> SelectionResult:
    """
    Select certificates based on include and ignore lists.

    Selection rules (in order of precedence):
    1. ignore_list ALWAYS takes precedence - certificates in this list are NEVER processed
    2. If include_list is empty/None - process ALL certificates (minus ignored)
    3. If include_list has entries - ONLY process certificates in this list (minus ignored)

    Args:
        all_certificates: List of all certificate objects from Key Vault
        include_list: Optional list of certificate names to include.
                     If empty/None, all certificates are candidates.
        ignore_list: Optional list of certificate names to always exclude.
        name_extractor: Optional function to extract name from certificate object.
                       Defaults to using .name attribute.

    Returns:
        SelectionResult with selected certificates and detailed selection info

    Example:
        >>> certs = [cert1, cert2, cert3, cert4]  # names: a, b, c, d
        >>> result = select_certificates(
        ...     certs,
        ...     include_list=["a", "b", "c"],
        ...     ignore_list=["b"],
        ... )
        >>> [c.name for c in result.selected]  # ["a", "c"]
        >>> result.ignored  # ["b"]
        >>> result.excluded  # ["d"]
    """
    include_list = include_list or []
    ignore_list = ignore_list or []

    # Default name extractor uses .name attribute
    if name_extractor is None:
        name_extractor = lambda cert: cert.name

    # Convert to sets for O(1) lookup
    include_set = set(include_list)
    ignore_set = set(ignore_list)

    # Determine if we're in "include mode" (explicit whitelist)
    include_mode = len(include_set) > 0

    selected = []
    ignored = []
    excluded = []
    selections = []

    for cert in all_certificates:
        cert_name = name_extractor(cert)

        # Rule 1: ignore_list always takes precedence
        if cert_name in ignore_set:
            ignored.append(cert_name)
            selections.append(CertificateSelection(
                name=cert_name,
                selected=False,
                reason=SelectionReason.IGNORED,
            ))
            continue

        # Rule 2 & 3: Check include_list
        if include_mode:
            # Include mode: only process if in include_list
            if cert_name in include_set:
                selected.append(cert)
                selections.append(CertificateSelection(
                    name=cert_name,
                    selected=True,
                    reason=SelectionReason.INCLUDED,
                ))
            else:
                excluded.append(cert_name)
                selections.append(CertificateSelection(
                    name=cert_name,
                    selected=False,
                    reason=SelectionReason.NOT_IN_INCLUDE_LIST,
                ))
        else:
            # No include_list: process all (not ignored)
            selected.append(cert)
            selections.append(CertificateSelection(
                name=cert_name,
                selected=True,
                reason=SelectionReason.INCLUDED,
            ))

    return SelectionResult(
        selected=selected,
        ignored=ignored,
        excluded=excluded,
        total_discovered=len(all_certificates),
        selections=selections,
    )


def normalize_san_signature(domains: List[str]) -> FrozenSet[str]:
    """
    Create a normalized SAN signature for duplicate detection.

    The signature is order-independent and case-insensitive,
    allowing identification of certificates with identical domain coverage.

    Args:
        domains: List of domain names (CN + SANs)

    Returns:
        Frozen set of normalized domain names for comparison
    """
    return frozenset(d.lower().strip() for d in domains if d)


def generate_certificate_filename(
    vault_name: str,
    cert_name: str,
    date: Optional[datetime] = None,
) -> str:
    """
    Generate consistent certificate filename.

    Format: <vault_name>-<cert_name>-<YYYYMMDD>.pfx

    Args:
        vault_name: Name of the Key Vault
        cert_name: Name of the certificate
        date: Date to use in filename (defaults to current date)

    Returns:
        Formatted filename string

    Examples:
        >>> generate_certificate_filename("prod-keyvault", "api-cert")
        "prod-keyvault-api-cert-20251225.pfx"
    """
    if date is None:
        date = datetime.now(timezone.utc)
    date_str = date.strftime("%Y%m%d")
    return f"{vault_name}-{cert_name}-{date_str}.pfx"


def save_pfx_artifact(
    pfx_data: bytes,
    artifact_dir: str,
    vault_name: str,
    cert_name: str,
    date: Optional[datetime] = None,
) -> str:
    """
    Save PFX certificate to artifact directory with consistent naming.

    Args:
        pfx_data: PFX certificate data as bytes
        artifact_dir: Directory to save the artifact
        vault_name: Name of the Key Vault
        cert_name: Name of the certificate
        date: Date to use in filename (defaults to current date)

    Returns:
        Full path to the saved artifact file
    """
    os.makedirs(artifact_dir, exist_ok=True)
    filename = generate_certificate_filename(vault_name, cert_name, date)
    artifact_path = os.path.join(artifact_dir, filename)
    with open(artifact_path, "wb") as f:
        f.write(pfx_data)
    return artifact_path
