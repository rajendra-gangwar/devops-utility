"""
Azure Key Vault operations.

Handles certificate discovery, retrieval, and upload operations
for Azure Key Vault.
"""

from datetime import datetime, timezone
from typing import List, Optional, Dict, Any
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .logger import get_logger

# Azure SDK imports with graceful handling
try:
    from azure.identity import DefaultAzureCredential
    from azure.keyvault.certificates import CertificateClient
    from azure.core.exceptions import (
        AzureError,
        ResourceNotFoundError,
        ClientAuthenticationError,
    )
    AZURE_SDK_AVAILABLE = True
except ImportError:
    AZURE_SDK_AVAILABLE = False


class KeyVaultError(Exception):
    """Raised when Key Vault operations fail."""
    pass


class AuthenticationError(KeyVaultError):
    """Raised when authentication to Key Vault fails."""
    pass


@dataclass
class CertificateInfo:
    """
    Certificate information from Key Vault.

    Contains metadata and parsed certificate details.
    """
    name: str
    vault_name: str
    vault_url: str
    domains: List[str]
    expires_on: Optional[datetime]
    issuer: Optional[str]
    thumbprint: Optional[str]
    enabled: bool = True


class KeyVaultClient:
    """
    Client for Azure Key Vault certificate operations.

    Uses DefaultAzureCredential for flexible authentication supporting:
    - Environment variables (Service Principal)
    - Managed Identity
    - Azure CLI credentials
    - GitHub OIDC (when running in GitHub Actions)
    """

    def __init__(self, vault_url: str):
        """
        Initialize the Key Vault client.

        Args:
            vault_url: Full URL to the Azure Key Vault

        Raises:
            KeyVaultError: If Azure SDK is not installed
        """
        if not AZURE_SDK_AVAILABLE:
            raise KeyVaultError(
                "Azure SDK not installed. "
                "Install with: pip install azure-identity azure-keyvault-certificates"
            )

        self.vault_url = vault_url
        self.vault_name = vault_url.split("//")[1].split(".")[0]
        self.logger = get_logger()
        self._client: Optional[CertificateClient] = None
        self._credential = None

    def _connect(self) -> None:
        """
        Establish connection to Azure Key Vault.

        Raises:
            AuthenticationError: If authentication fails
        """
        try:
            self._credential = DefaultAzureCredential()
            self._client = CertificateClient(
                vault_url=self.vault_url,
                credential=self._credential,
            )

            # Test the connection
            list(self._client.list_properties_of_certificates(max_page_size=1))
            self.logger.debug(f"Connected to Key Vault: {self.vault_name}")

        except ClientAuthenticationError as e:
            raise AuthenticationError(
                f"Failed to authenticate to Azure Key Vault: {e}"
            )
        except AzureError as e:
            raise KeyVaultError(f"Failed to connect to Azure Key Vault: {e}")

    @property
    def client(self) -> CertificateClient:
        """Get the certificate client, connecting if necessary."""
        if self._client is None:
            self._connect()
        return self._client

    def list_certificates(self) -> List[CertificateInfo]:
        """
        List all certificates in the Key Vault with their details.

        Returns:
            List of CertificateInfo objects
        """
        certificates = []

        try:
            for cert_props in self.client.list_properties_of_certificates():
                # Get full certificate details
                cert_info = self._get_certificate_info(cert_props.name)
                if cert_info:
                    certificates.append(cert_info)

            return certificates

        except AzureError as e:
            self.logger.error(f"Error listing certificates: {e}")
            raise KeyVaultError(f"Failed to list certificates: {e}")

    def _get_certificate_info(self, cert_name: str) -> Optional[CertificateInfo]:
        """
        Get detailed information about a certificate.

        Args:
            cert_name: Name of the certificate

        Returns:
            CertificateInfo or None if not found
        """
        try:
            certificate = self.client.get_certificate(cert_name)
            props = certificate.properties

            # Extract domains from certificate
            domains = self._extract_domains(certificate.cer)

            # Extract issuer from certificate
            issuer = self._extract_issuer(certificate.cer)

            # Ensure timezone-aware expiration
            expires_on = props.expires_on
            if expires_on and expires_on.tzinfo is None:
                expires_on = expires_on.replace(tzinfo=timezone.utc)

            return CertificateInfo(
                name=props.name,
                vault_name=self.vault_name,
                vault_url=self.vault_url,
                domains=domains,
                expires_on=expires_on,
                issuer=issuer,
                thumbprint=(
                    props.x509_thumbprint.hex()
                    if props.x509_thumbprint
                    else None
                ),
                enabled=props.enabled,
            )

        except ResourceNotFoundError:
            self.logger.debug(f"Certificate not found: {cert_name}")
            return None
        except Exception as e:
            self.logger.error(f"Error getting certificate {cert_name}: {e}")
            return None

    def _extract_domains(self, cer_bytes: bytes) -> List[str]:
        """
        Extract domain names from certificate.

        Args:
            cer_bytes: DER-encoded certificate bytes

        Returns:
            List of domain names from CN and SANs
        """
        if not cer_bytes:
            return []

        try:
            cert = x509.load_der_x509_certificate(cer_bytes, default_backend())
            domains = []

            # Get Common Name (CN)
            for attribute in cert.subject:
                if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                    cn = attribute.value
                    if cn and cn not in domains:
                        domains.append(cn)

            # Get Subject Alternative Names
            try:
                san_ext = cert.extensions.get_extension_for_oid(
                    x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
                )
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        if name.value not in domains:
                            domains.append(name.value)
            except x509.ExtensionNotFound:
                pass

            return domains

        except Exception as e:
            self.logger.warning(f"Error extracting domains: {e}")
            return []

    def _extract_issuer(self, cer_bytes: bytes) -> Optional[str]:
        """
        Extract issuer organization from certificate.

        Args:
            cer_bytes: DER-encoded certificate bytes

        Returns:
            Issuer organization name or None
        """
        if not cer_bytes:
            return None

        try:
            cert = x509.load_der_x509_certificate(cer_bytes, default_backend())

            # Get Organization (O) from issuer
            for attribute in cert.issuer:
                if attribute.oid == x509.oid.NameOID.ORGANIZATION_NAME:
                    return attribute.value

            # Fallback to Common Name
            for attribute in cert.issuer:
                if attribute.oid == x509.oid.NameOID.COMMON_NAME:
                    return attribute.value

            return None

        except Exception as e:
            self.logger.warning(f"Error extracting issuer: {e}")
            return None

    def import_certificate(
        self,
        cert_name: str,
        pfx_data: bytes,
        password: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Import a PFX certificate into Key Vault.

        Args:
            cert_name: Name for the certificate in Key Vault
            pfx_data: PFX certificate data as bytes
            password: Password for the PFX file (if any)

        Returns:
            Dictionary with imported certificate details

        Raises:
            KeyVaultError: If import fails
        """
        try:
            # Don't specify policy - Azure will use existing certificate's policy
            # for updates, or infer from content for new certificates
            certificate = self.client.import_certificate(
                certificate_name=cert_name,
                certificate_bytes=pfx_data,
                password=password,
                enabled=True,
            )

            self.logger.info(f"Imported certificate: {cert_name}")

            return {
                "name": certificate.properties.name,
                "version": certificate.properties.version,
                "expires_on": certificate.properties.expires_on,
                "thumbprint": (
                    certificate.properties.x509_thumbprint.hex()
                    if certificate.properties.x509_thumbprint
                    else None
                ),
            }

        except AzureError as e:
            raise KeyVaultError(f"Failed to import certificate {cert_name}: {e}")


def get_certificate_details(
    client: KeyVaultClient,
    cert_name: str,
) -> Optional[CertificateInfo]:
    """
    Get certificate details from Key Vault.

    Args:
        client: KeyVaultClient instance
        cert_name: Name of the certificate

    Returns:
        CertificateInfo or None if not found
    """
    return client._get_certificate_info(cert_name)


def upload_certificate(
    client: KeyVaultClient,
    cert_name: str,
    pfx_data: bytes,
    password: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Upload a certificate to Key Vault.

    Args:
        client: KeyVaultClient instance
        cert_name: Name for the certificate
        pfx_data: PFX certificate data
        password: PFX password (if any)

    Returns:
        Dictionary with uploaded certificate details
    """
    return client.import_certificate(cert_name, pfx_data, password)
