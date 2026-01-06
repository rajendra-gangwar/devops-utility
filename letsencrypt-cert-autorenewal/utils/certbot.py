"""
Certbot renewal wrapper.

Handles running Certbot for certificate renewal with DNS-01 challenge
using either AWS Route53 or Azure DNS.
"""

import os
import subprocess
import tempfile
import shutil
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .logger import get_logger
from .config_loader import Config


def get_certificate_expiry(cert_path: str) -> datetime:
    """
    Extract the expiry date from a PEM certificate file.

    Args:
        cert_path: Path to the PEM certificate file

    Returns:
        Certificate expiry datetime (timezone-aware UTC)
    """
    with open(cert_path, "rb") as f:
        cert_data = f.read()
    cert = x509.load_pem_x509_certificate(cert_data, default_backend())
    return cert.not_valid_after_utc


class CertbotError(Exception):
    """Raised when Certbot operations fail."""
    pass


def _check_certbot_installed() -> str:
    """
    Check if Certbot is installed and return its path.

    Returns:
        Path to Certbot executable

    Raises:
        CertbotError: If Certbot is not installed
    """
    certbot_path = shutil.which("certbot")
    if not certbot_path:
        raise CertbotError(
            "Certbot not found. Install with: pip install certbot"
        )
    return certbot_path


def _get_github_oidc_token() -> str:
    """
    Fetch GitHub Actions OIDC token for AWS authentication.

    In GitHub Actions, the OIDC token is obtained by making a request to
    ACTIONS_ID_TOKEN_REQUEST_URL with ACTIONS_ID_TOKEN_REQUEST_TOKEN.

    Returns:
        The OIDC JWT token string

    Raises:
        CertbotError: If not running in GitHub Actions or token fetch fails
    """
    import requests

    token_url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL")
    token_bearer = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN")

    if not token_url or not token_bearer:
        raise CertbotError(
            "GitHub OIDC environment not detected.\n"
            "Ensure workflow has 'permissions: id-token: write' and is running in GitHub Actions."
        )

    # Request token with AWS STS audience
    try:
        response = requests.get(
            f"{token_url}&audience=sts.amazonaws.com",
            headers={"Authorization": f"Bearer {token_bearer}"},
            timeout=10,
        )
        response.raise_for_status()
        return response.json()["value"]
    except requests.RequestException as e:
        raise CertbotError(f"Failed to fetch GitHub OIDC token: {e}")


def _assume_role_with_web_identity(
    role_arn: str,
    oidc_token: str,
    region: str = "us-east-1",
    session_name: str = "certbot-renewal",
) -> Dict[str, str]:
    """
    Assume an AWS IAM role using OIDC web identity token.

    Uses AWS STS AssumeRoleWithWebIdentity to exchange the GitHub OIDC
    token for temporary AWS credentials.

    Args:
        role_arn: The ARN of the IAM role to assume
        oidc_token: The OIDC JWT token from GitHub
        region: AWS region for STS endpoint
        session_name: Name for the assumed role session

    Returns:
        Dictionary with AWS credential environment variables

    Raises:
        CertbotError: If role assumption fails
    """
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config as BotoConfig

    logger = get_logger()
    logger.info(f"Assuming AWS role via OIDC: {role_arn}")

    try:
        # Create STS client without credentials (using OIDC token instead)
        sts_client = boto3.client(
            "sts",
            region_name=region,
            config=BotoConfig(signature_version=UNSIGNED),
        )

        # Assume role with web identity
        response = sts_client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=session_name,
            WebIdentityToken=oidc_token,
            DurationSeconds=3600,  # 1 hour
        )

        creds = response["Credentials"]

        # Verify credentials work
        verify_client = boto3.client(
            "sts",
            region_name=region,
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
        identity = verify_client.get_caller_identity()
        logger.debug(f"Authenticated as: {identity['Arn']}")

        return {
            "AWS_ACCESS_KEY_ID": creds["AccessKeyId"],
            "AWS_SECRET_ACCESS_KEY": creds["SecretAccessKey"],
            "AWS_SESSION_TOKEN": creds["SessionToken"],
            "AWS_DEFAULT_REGION": region,
        }

    except Exception as e:
        raise CertbotError(f"Failed to assume AWS role with OIDC: {e}")


def _get_aws_region(dns_zone_info: Optional[Dict[str, Any]] = None) -> str:
    """
    Determine the AWS region to use.

    Priority (highest to lowest):
    1. dns_zone_info["region"] from config.yaml
    2. AWS_DEFAULT_REGION environment variable
    3. Default: eu-west-1

    Args:
        dns_zone_info: DNS zone configuration

    Returns:
        AWS region string
    """
    # Check config first
    if dns_zone_info and dns_zone_info.get("region"):
        return dns_zone_info["region"]

    # Check environment variable
    if os.environ.get("AWS_DEFAULT_REGION"):
        return os.environ["AWS_DEFAULT_REGION"]

    # Default
    return "eu-west-1"


def _setup_aws_credentials(dns_zone_info: Optional[Dict[str, Any]] = None) -> Dict[str, str]:
    """
    Setup AWS credentials for Route53.

    Authentication flow (in order of priority):
    1. GitHub OIDC + AssumeRoleWithWebIdentity (role_arn from config)
    2. Pre-existing AWS credentials in environment (for local testing)

    For GitHub Actions:
    - Fetches OIDC token from GitHub
    - Uses AssumeRoleWithWebIdentity to assume role specified in config.yaml
    - No aws-actions/configure-aws-credentials needed

    Args:
        dns_zone_info: DNS zone configuration with role_arn (required for OIDC)

    Returns:
        Dictionary of environment variables to set

    Raises:
        CertbotError: If AWS credentials cannot be obtained
    """
    logger = get_logger()

    # Get role ARN from config (required for OIDC auth)
    role_arn = dns_zone_info.get("role_arn") if dns_zone_info else None
    region = _get_aws_region(dns_zone_info)

    # Check if running in GitHub Actions with OIDC capability
    if os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL"):
        if not role_arn:
            raise CertbotError(
                "GitHub OIDC detected but no role_arn configured.\n"
                "Add 'role_arn' to the DNS provider account in config.yaml"
            )

        logger.info("Using GitHub OIDC for AWS authentication")

        # Fetch GitHub OIDC token
        oidc_token = _get_github_oidc_token()

        # Assume the role using OIDC token
        return _assume_role_with_web_identity(
            role_arn=role_arn,
            oidc_token=oidc_token,
            region=region,
        )

    # Fallback: Check for pre-existing credentials (local testing)
    if os.environ.get("AWS_ACCESS_KEY_ID"):
        logger.debug("Using existing AWS credentials from environment")
        return {}

    # No authentication method available
    raise CertbotError(
        "AWS credentials not configured.\n"
        "In GitHub Actions: Ensure workflow has 'permissions: id-token: write'\n"
        "For local testing: Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
    )


def _setup_azure_credentials(
    dns_zone_info: Optional[Dict[str, Any]] = None,
) -> tuple:
    """
    Setup Azure DNS credentials for Certbot.

    Creates a temporary credentials file for certbot-dns-azure.
    Supports both Workload Identity (OIDC) and Service Principal authentication.

    Args:
        dns_zone_info: DNS zone configuration

    Returns:
        Tuple of (environment variables, credentials file path)

    Raises:
        CertbotError: If Azure credentials are not available
    """
    logger = get_logger()

    # Get subscription and resource group from dns_zone_info (required)
    subscription_id = (
        dns_zone_info.get("subscription_id")
        if dns_zone_info
        else os.environ.get("AZURE_SUBSCRIPTION_ID")
    )
    resource_group = (
        dns_zone_info.get("resource_group")
        if dns_zone_info
        else os.environ.get("AZURE_DNS_RESOURCE_GROUP")
    )
    zone = dns_zone_info.get("zone", "") if dns_zone_info else ""

    if not subscription_id:
        raise CertbotError("Azure subscription ID not configured")
    if not resource_group:
        raise CertbotError("Azure DNS resource group not configured")

    # Determine authentication method
    # Priority: Azure CLI (from azure/login OIDC) > Service Principal with Secret
    use_cli_credentials = False

    # Check for Azure CLI session (from azure/login action with OIDC)
    # In GitHub Actions with azure/login using OIDC, AZURE_CLIENT_SECRET is not set
    has_client_id = os.environ.get("AZURE_CLIENT_ID")
    has_client_secret = os.environ.get("AZURE_CLIENT_SECRET")

    if has_client_id and not has_client_secret:
        # OIDC via azure/login - use Azure CLI credentials
        use_cli_credentials = True
        logger.info("Using Azure CLI credentials (OIDC) for DNS authentication")
    elif has_client_id and has_client_secret:
        # Service Principal with secret (legacy)
        logger.info("Using Azure Service Principal for DNS authentication")
    else:
        raise CertbotError(
            "Azure credentials not configured.\n"
            "For OIDC: Use azure/login action with OIDC federation\n"
            "For Service Principal: Set AZURE_CLIENT_ID, AZURE_CLIENT_SECRET, AZURE_TENANT_ID"
        )

    # Build credentials file content
    if use_cli_credentials:
        # Azure CLI credentials (uses session from azure/login action)
        credentials_content = f"""\
# Azure DNS credentials for Certbot (Azure CLI)
dns_azure_use_cli_credentials = true
dns_azure_environment = AzurePublicCloud

# DNS zone configuration
dns_azure_zone1 = {zone}:/subscriptions/{subscription_id}/resourceGroups/{resource_group}
"""
    else:
        # Service Principal configuration (legacy with secret)
        tenant_id = os.environ.get("AZURE_TENANT_ID")
        if not tenant_id:
            raise CertbotError("AZURE_TENANT_ID is required for Service Principal authentication")

        credentials_content = f"""\
# Azure DNS credentials for Certbot (Service Principal)
dns_azure_sp_client_id = {os.environ['AZURE_CLIENT_ID']}
dns_azure_sp_client_secret = {os.environ['AZURE_CLIENT_SECRET']}
dns_azure_tenant_id = {tenant_id}

# DNS zone configuration
dns_azure_zone1 = {zone}:/subscriptions/{subscription_id}/resourceGroups/{resource_group}
"""

    # Write to temp file
    fd, creds_path = tempfile.mkstemp(suffix=".ini", prefix="azure_dns_")
    try:
        os.write(fd, credentials_content.encode())
    finally:
        os.close(fd)

    # Set restrictive permissions
    os.chmod(creds_path, 0o600)

    logger.debug(f"Created Azure credentials file: {creds_path}")

    return {}, creds_path


# Let's Encrypt ACME server URLs
LETSENCRYPT_PRODUCTION_URL = "https://acme-v02.api.letsencrypt.org/directory"
LETSENCRYPT_STAGING_URL = "https://acme-staging-v02.api.letsencrypt.org/directory"


def run_certbot_renewal(
    domains: List[str],
    dns_provider: str,
    email: str,
    config: Config,
    dns_zone_info: Optional[Dict[str, Any]] = None,
    use_staging: bool = False,
) -> Dict[str, str]:
    """
    Run Certbot to renew a certificate.

    Args:
        domains: List of domains for the certificate
        dns_provider: DNS provider ("route53" or "azure")
        email: Email for Let's Encrypt registration
        config: Global configuration
        dns_zone_info: Optional DNS zone configuration
        use_staging: If True, use Let's Encrypt staging environment

    Returns:
        Dictionary with paths to certificate files:
        - cert: Path to certificate file
        - privkey: Path to private key file
        - chain: Path to certificate chain file
        - fullchain: Path to full chain file

    Raises:
        CertbotError: If renewal fails
    """
    logger = get_logger()

    # Check Certbot is installed
    certbot_path = _check_certbot_installed()

    # Determine ACME server URL
    if use_staging:
        acme_server = LETSENCRYPT_STAGING_URL
        logger.info("Using Let's Encrypt STAGING environment")
    else:
        acme_server = LETSENCRYPT_PRODUCTION_URL
        logger.debug("Using Let's Encrypt production environment")

    # Setup directories
    work_dir = Path(config.settings.certbot_work_dir)
    logs_dir = Path(config.settings.certbot_logs_dir)
    config_dir = Path(config.settings.certbot_config_dir)

    for dir_path in [work_dir, logs_dir, config_dir]:
        dir_path.mkdir(parents=True, exist_ok=True)

    # Build base command
    cmd = [
        certbot_path, "certonly",
        "--non-interactive",
        "--agree-tos",
        "--server", acme_server,
        "--work-dir", str(work_dir),
        "--logs-dir", str(logs_dir),
        "--config-dir", str(config_dir),
    ]

    # Add email or register without email
    if email and email.strip():
        cmd.extend(["--email", email.strip()])
    else:
        logger.warning("No email configured - registering without email (not recommended)")
        cmd.append("--register-unsafely-without-email")

    # Add domains
    for domain in domains:
        cmd.extend(["-d", domain])

    # Add key type configuration
    key_type = config.settings.key_type.lower()
    cmd.extend(["--key-type", key_type])

    if key_type == "rsa":
        cmd.extend(["--rsa-key-size", str(config.settings.rsa_key_size)])
        logger.info(f"Using RSA key with {config.settings.rsa_key_size}-bit size")
    elif key_type == "ecdsa":
        cmd.extend(["--elliptic-curve", config.settings.elliptic_curve])
        logger.info(f"Using ECDSA key with {config.settings.elliptic_curve} curve")

    # Setup provider-specific options
    env_vars = os.environ.copy()
    azure_creds_file = None

    try:
        if dns_provider == "route53":
            logger.info("Using Route53 for DNS validation")
            aws_env = _setup_aws_credentials(dns_zone_info)
            env_vars.update(aws_env)
            cmd.extend(["--dns-route53"])

        elif dns_provider == "azure":
            logger.info("Using Azure DNS for DNS validation")
            azure_env, azure_creds_file = _setup_azure_credentials(dns_zone_info)
            env_vars.update(azure_env)
            cmd.extend([
                "--authenticator", "dns-azure",
                "--dns-azure-config", azure_creds_file,
            ])
        else:
            raise CertbotError(f"Unknown DNS provider: {dns_provider}")

        # Run Certbot
        logger.debug(f"Running: {' '.join(cmd)}")

        result = subprocess.run(
            cmd,
            env=env_vars,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
        )

        if result.returncode != 0:
            logger.error(f"Certbot stderr: {result.stderr}")
            raise CertbotError(f"Certbot failed: {result.stderr}")

        logger.debug(f"Certbot stdout: {result.stdout}")

        # Find certificate files
        primary_domain = domains[0].replace("*.", "")
        cert_dir = config_dir / "live" / primary_domain

        if not cert_dir.exists():
            raise CertbotError(f"Certificate directory not found: {cert_dir}")

        return {
            "cert": str(cert_dir / "cert.pem"),
            "privkey": str(cert_dir / "privkey.pem"),
            "chain": str(cert_dir / "chain.pem"),
            "fullchain": str(cert_dir / "fullchain.pem"),
        }

    finally:
        # Cleanup Azure credentials file
        if azure_creds_file and os.path.exists(azure_creds_file):
            os.unlink(azure_creds_file)


def run_certbot_create(
    domains: List[str],
    dns_provider: str,
    email: str,
    config: Config,
    dns_zone_info: Optional[Dict[str, Any]] = None,
    use_staging: bool = False,
) -> Dict[str, str]:
    """
    Run Certbot to create a new certificate.

    This is functionally identical to renewal - Certbot's 'certonly' command
    handles both new certificate creation and renewal.

    Args:
        domains: List of domains for the certificate
        dns_provider: DNS provider ("route53" or "azure")
        email: Email for Let's Encrypt registration
        config: Global configuration
        dns_zone_info: Optional DNS zone configuration
        use_staging: If True, use Let's Encrypt staging environment

    Returns:
        Dictionary with paths to certificate files:
        - cert: Path to certificate file
        - privkey: Path to private key file
        - chain: Path to certificate chain file
        - fullchain: Path to full chain file

    Raises:
        CertbotError: If certificate creation fails
    """
    # Certificate creation uses the same Certbot command as renewal
    return run_certbot_renewal(
        domains=domains,
        dns_provider=dns_provider,
        email=email,
        config=config,
        dns_zone_info=dns_zone_info,
        use_staging=use_staging,
    )


def convert_to_pfx(
    cert_path: str,
    key_path: str,
    chain_path: str,
    password: Optional[str] = None,
) -> bytes:
    """
    Convert PEM certificate files to PFX format.

    Args:
        cert_path: Path to certificate file
        key_path: Path to private key file
        chain_path: Path to certificate chain file
        password: Optional password for PFX file

    Returns:
        PFX data as bytes

    Raises:
        CertbotError: If conversion fails
    """
    logger = get_logger()

    # Check OpenSSL is available
    openssl_path = shutil.which("openssl")
    if not openssl_path:
        raise CertbotError("OpenSSL not found")

    # Create temporary file for PFX output
    fd, pfx_path = tempfile.mkstemp(suffix=".pfx")
    os.close(fd)

    try:
        # Build OpenSSL command
        # Note: -legacy flag is required for OpenSSL 3.x compatibility with Azure Key Vault
        # OpenSSL 3.x uses newer encryption algorithms by default that Azure doesn't support
        cmd = [
            openssl_path, "pkcs12", "-export",
            "-legacy",
            "-inkey", key_path,
            "-in", cert_path,
            "-certfile", chain_path,
            "-out", pfx_path,
        ]

        # Add password
        if password:
            cmd.extend(["-passout", f"pass:{password}"])
        else:
            cmd.extend(["-passout", "pass:"])

        logger.debug(f"Converting to PFX: {cert_path}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode != 0:
            raise CertbotError(f"PFX conversion failed: {result.stderr}")

        # Read PFX data
        with open(pfx_path, "rb") as f:
            pfx_data = f.read()

        return pfx_data

    finally:
        # Cleanup temp file
        if os.path.exists(pfx_path):
            os.unlink(pfx_path)
