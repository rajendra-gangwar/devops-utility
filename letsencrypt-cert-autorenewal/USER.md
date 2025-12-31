# User Guide: Let's Encrypt Certificate Auto-Renewal

This guide provides step-by-step instructions for setting up and using the Let's Encrypt Certificate Auto-Renewal tool.

## Table of Contents
- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Configuration Guide](#configuration-guide)
- [Environment Variables](#environment-variables)
- [Usage Examples](#usage-examples)
- [GitHub Actions Setup](#github-actions-setup)
- [Error Reference & Troubleshooting](#error-reference--troubleshooting)
- [Pre-Production Checklist](#pre-production-checklist)

---

## Quick Start

### 1. Install Dependencies

```bash
# Clone and enter the directory
cd letsencrypt-cert-autorenewal

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt
```

### 2. Create Configuration File

```bash
cp config.yaml config.local.yaml
```

### 3. Configure Minimum Settings

Edit `config.local.yaml`:

```yaml
settings:
  expiration_threshold_days: 10
  letsencrypt_email: "your-email@example.com"

dns_providers:
  azure:
    subscriptions:
      "your-subscription-id":
        zones:
          - zone: "yourdomain.com"
            resource_group: "your-dns-resource-group"

vaults:
  - name: "your-keyvault"
    url: "https://your-keyvault.vault.azure.net/"
    ignore_certificates: []
```

### 4. Test with Dry Run

```bash
# Login to Azure first
az login

# Run in dry-run mode
python main.py --auto --config config.local.yaml --dry-run --verbose
```

### 5. Run Actual Renewal

```bash
python main.py --auto --config config.local.yaml --verbose
```

---

## Prerequisites

### System Requirements

| Requirement | Version | Installation |
|-------------|---------|--------------|
| Python | 3.8+ | `apt install python3` or download from python.org |
| Certbot | Latest | Installed via requirements.txt |
| OpenSSL | Any | Usually pre-installed; `apt install openssl` if needed |

### Azure Requirements

#### Key Vault Permissions

Your identity (user, service principal, or managed identity) needs these RBAC roles on each Key Vault:

| Role | Purpose |
|------|---------|
| Key Vault Certificates Officer | Read, create, update certificates |

Or these specific permissions:
- `Microsoft.KeyVault/vaults/certificates/read`
- `Microsoft.KeyVault/vaults/certificates/create`
- `Microsoft.KeyVault/vaults/certificates/update`

#### Azure DNS Permissions (if using Azure DNS)

| Role | Scope | Purpose |
|------|-------|---------|
| DNS Zone Contributor | Resource group containing DNS zones | Create/delete DNS records for ACME challenge |

### AWS Requirements (if using Route53)

#### IAM Policy

Create an IAM policy with these permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "route53:GetChange",
        "route53:ChangeResourceRecordSets",
        "route53:ListHostedZones"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Authentication Options

1. **GitHub Actions OIDC** (Recommended): Configure OIDC trust and specify `role_arn` in config
2. **Local Testing**: Set `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` environment variables

### Notification Requirements

#### Email (SendGrid)

1. Create a SendGrid account at [sendgrid.com](https://sendgrid.com)
2. Create an API key with "Mail Send" permission
3. Verify your sender email address in SendGrid
4. Set `SENDGRID_API_KEY` environment variable

#### Microsoft Teams

1. Open the Teams channel where you want notifications
2. Click `...` > **Connectors** > **Incoming Webhook**
3. Configure the webhook and copy the URL
4. Set `TEAMS_WEBHOOK_URL` environment variable

**Note:** Teams webhooks only work with public channels, not private channels.

---

## Configuration Guide

### Complete config.yaml Structure

```yaml
# ===================
# GLOBAL SETTINGS
# ===================
settings:
  # Days before expiration to trigger renewal (1-90)
  expiration_threshold_days: 10

  # Email for Let's Encrypt account (recommended)
  letsencrypt_email: "devops@example.com"

  # Continue processing if one certificate fails
  continue_on_error: true

  # Delete local cert files after upload
  cleanup_after_upload: true

  # Certbot working directories
  certbot_work_dir: "/tmp/certbot"
  certbot_logs_dir: "/tmp/certbot-logs"
  certbot_config_dir: "/tmp/certbot-config"

  # Certificate key type: "rsa" or "ecdsa"
  key_type: "rsa"

  # RSA key size (if key_type is rsa): 2048, 3072, or 4096
  rsa_key_size: 2048

  # ECDSA curve (if key_type is ecdsa): secp256r1 or secp384r1
  elliptic_curve: "secp384r1"

# ===================
# DNS PROVIDERS
# ===================
dns_providers:
  # AWS Route53 Configuration
  route53:
    accounts:
      "123456789012":  # AWS Account ID
        hosted_zones:
          - "example.com"
          - "example.org"
        # IAM role for GitHub OIDC
        role_arn: "arn:aws:iam::123456789012:role/CertbotRoute53Role"
        # Optional: AWS region (default: eu-west-1)
        region: "us-east-1"

  # Azure DNS Configuration
  azure:
    subscriptions:
      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee":  # Subscription ID
        zones:
          - zone: "contoso.com"
            resource_group: "dns-rg-contoso"
          - zone: "fabrikam.com"
            resource_group: "dns-rg-fabrikam"

# ===================
# KEY VAULTS
# ===================
vaults:
  # Example 1: Process only specific certificates (whitelist mode)
  - name: "prod-keyvault"
    url: "https://prod-keyvault.vault.azure.net/"
    include_certificates:
      - "api-cert"
      - "web-cert"
    ignore_certificates:
      - "legacy-cert"

  # Example 2: Process all certificates except ignored (default mode)
  - name: "staging-keyvault"
    url: "https://staging-keyvault.vault.azure.net/"
    ignore_certificates:
      - "test-cert"

# ===================
# NOTIFICATIONS
# ===================
notifications:
  # Email via SendGrid
  email:
    enabled: true
    from_email: "certificates@example.com"
    to_emails:
      - "devops@example.com"
      - "security@example.com"
    # Optional: custom template
    # template_path: "templates/email_notification.html"

  # Microsoft Teams via Webhook
  teams:
    enabled: true
    # Webhook URL from TEAMS_WEBHOOK_URL environment variable
    # Optional: custom template
    # template_path: "templates/teams_notification.json"
```

### Certificate Selection Rules

The tool uses these rules to determine which certificates to process:

| Configuration | Behavior |
|---------------|----------|
| `ignore_certificates` specified | These are **NEVER** processed (highest priority) |
| `include_certificates` empty or missing | Process **ALL** certificates (minus ignored) |
| `include_certificates` specified | Process **ONLY** these certificates (minus ignored) |

**Example scenarios:**

```yaml
# Scenario 1: Process only api-cert and web-cert
include_certificates: ["api-cert", "web-cert"]
ignore_certificates: []
# Result: Only api-cert and web-cert are processed

# Scenario 2: Process all except legacy-cert
include_certificates: []
ignore_certificates: ["legacy-cert"]
# Result: All certificates except legacy-cert are processed

# Scenario 3: Mixed - whitelist with blacklist
include_certificates: ["api-cert", "web-cert", "legacy-cert"]
ignore_certificates: ["legacy-cert"]
# Result: Only api-cert and web-cert (legacy-cert is ignored despite being in include)
```

---

## Environment Variables

### Required Variables

| Variable | When Required | Description |
|----------|---------------|-------------|
| `AZURE_CLIENT_ID` | Always (GitHub Actions) | Azure AD application client ID |
| `AZURE_TENANT_ID` | Always (GitHub Actions) | Azure AD tenant ID |

### Optional Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `AZURE_SUBSCRIPTION_ID` | Default Azure subscription | From config |
| `PFX_PASSWORD` | Password for PFX certificate file | Empty (no password) |
| `AWS_DEFAULT_REGION` | Override AWS region | `eu-west-1` |
| `AWS_ACCESS_KEY_ID` | AWS authentication (local testing) | - |
| `AWS_SECRET_ACCESS_KEY` | AWS authentication (local testing) | - |

### Notification Variables

| Variable | When Required | Description |
|----------|---------------|-------------|
| `SENDGRID_API_KEY` | If email notifications enabled | SendGrid API key |
| `TEAMS_WEBHOOK_URL` | If Teams notifications enabled | Teams incoming webhook URL |

### Setting Environment Variables

**Linux/macOS:**
```bash
export SENDGRID_API_KEY="SG.xxxxxxxxxxxx"
export TEAMS_WEBHOOK_URL="https://outlook.office.com/webhook/..."
export PFX_PASSWORD="your-secure-password"
```

**GitHub Actions:**
Add to repository secrets, then reference in workflow:
```yaml
env:
  SENDGRID_API_KEY: ${{ secrets.SENDGRID_API_KEY }}
  TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
  PFX_PASSWORD: ${{ secrets.PFX_PASSWORD }}
```

---

## Usage Examples

### Automatic Mode (Recommended)

Scan all configured vaults and renew expiring certificates:

```bash
# Basic usage
python main.py --auto

# With specific config file
python main.py --auto --config config.local.yaml

# With verbose output
python main.py --auto --verbose

# Dry run (test without making changes)
python main.py --auto --dry-run

# Override expiration threshold
python main.py --auto --threshold 14
```

### Manual Renewal Mode

Renew a specific certificate:

```bash
python main.py --vault-name prod-keyvault --cert-name api-cert
```

### Create New Certificate

Create a new certificate and upload to Key Vault:

```bash
python main.py --task create \
    --san "example.com,www.example.com,api.example.com" \
    --vault-url https://my-keyvault.vault.azure.net/ \
    --subscription aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
    --cert-name my-new-cert

# Test with dry run first
python main.py --task create \
    --san "example.com" \
    --vault-url https://my-keyvault.vault.azure.net/ \
    --subscription aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
    --cert-name my-new-cert \
    --dry-run
```

### Override Certificate Key Type

```bash
# Use ECDSA instead of RSA
python main.py --auto --key-type ecdsa --elliptic-curve secp384r1

# Use larger RSA key
python main.py --auto --key-type rsa --rsa-key-size 4096
```

### JSON Output for CI/CD

```bash
python main.py --auto --json-summary
```

### All Command-Line Options

| Option | Description |
|--------|-------------|
| `--task {create,renew}` | Task type (default: renew) |
| `--auto` | Automatic mode: scan all vaults |
| `--vault-name NAME` | Manual mode: vault name |
| `--cert-name NAME` | Certificate name |
| `--san DOMAINS` | Create mode: comma-separated domains |
| `--vault-url URL` | Create mode: Key Vault URL |
| `--subscription ID` | Create mode: Azure subscription ID |
| `--config FILE` | Path to config file (default: config.yaml) |
| `--threshold DAYS` | Override expiration threshold |
| `--dry-run` | Test mode: no actual changes |
| `--verbose, -v` | Enable debug logging |
| `--no-color` | Disable colored output |
| `--pfx-password PWD` | Password for PFX file |
| `--key-type {rsa,ecdsa}` | Override key type |
| `--rsa-key-size {2048,3072,4096}` | Override RSA key size |
| `--elliptic-curve {secp256r1,secp384r1}` | Override ECDSA curve |
| `--aws-region REGION` | Override AWS region |
| `--json-summary` | Output JSON summary |

---

## GitHub Actions Setup

### Scheduled Certificate Renewal

Create `.github/workflows/cert-renewal.yaml`:

```yaml
name: Certificate Renewal

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM UTC
  workflow_dispatch:  # Manual trigger

permissions:
  id-token: write  # Required for OIDC
  contents: read

jobs:
  renew:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run certificate renewal
        env:
          AZURE_CLIENT_ID: ${{ vars.AZURE_CLIENT_ID }}
          AZURE_TENANT_ID: ${{ vars.AZURE_TENANT_ID }}
          PFX_PASSWORD: ${{ secrets.PFX_PASSWORD }}
          SENDGRID_API_KEY: ${{ secrets.SENDGRID_API_KEY }}
          TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}
        run: python main.py --auto --verbose
```

### Required GitHub Configuration

#### Repository Variables (Settings > Secrets and variables > Actions > Variables)

| Variable | Value |
|----------|-------|
| `AZURE_CLIENT_ID` | Your Azure AD app client ID |
| `AZURE_TENANT_ID` | Your Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | Your Azure subscription ID |

#### Repository Secrets (Settings > Secrets and variables > Actions > Secrets)

| Secret | Value |
|--------|-------|
| `PFX_PASSWORD` | Password for PFX files (optional) |
| `SENDGRID_API_KEY` | SendGrid API key (if using email) |
| `TEAMS_WEBHOOK_URL` | Teams webhook URL (if using Teams) |

### Azure OIDC Setup

1. **Create App Registration** in Azure AD
2. **Add Federated Credential:**
   - Issuer: `https://token.actions.githubusercontent.com`
   - Subject: `repo:your-org/your-repo:ref:refs/heads/main`
   - Audience: `api://AzureADTokenExchange`
3. **Grant Permissions:**
   - Key Vault Certificates Officer on each Key Vault
   - DNS Zone Contributor on DNS resource groups (if using Azure DNS)

### AWS OIDC Setup (if using Route53)

1. **Create OIDC Provider** in AWS IAM:
   - Provider URL: `https://token.actions.githubusercontent.com`
   - Audience: `sts.amazonaws.com`

2. **Create IAM Role** with trust policy:
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::ACCOUNT_ID:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:your-org/your-repo:*"
      }
    }
  }]
}
```

3. **Add role ARN to config.yaml:**
```yaml
dns_providers:
  route53:
    accounts:
      "123456789012":
        role_arn: "arn:aws:iam::123456789012:role/CertbotRoute53Role"
```

---

## Error Reference & Troubleshooting

### Configuration Errors (Exit Code 2)

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `Configuration file not found: config.yaml` | Config file doesn't exist | Create config.yaml or use `--config` to specify path |
| `Configuration file must be YAML (.yaml or .yml)` | Wrong file extension | Rename to .yaml or .yml |
| `Missing 'settings' section in configuration` | YAML structure incomplete | Add `settings:` section |
| `Missing 'vaults' section in configuration` | No vaults configured | Add `vaults:` section |
| `At least one vault must be configured` | Vaults list is empty | Add at least one vault |
| `Vault name is required` | Vault missing name | Add `name:` field to vault |
| `Vault URL is required` | Vault missing URL | Add `url:` field to vault |
| `Vault URL must start with https://` | Invalid URL format | Use `https://vaultname.vault.azure.net/` |
| `expiration_threshold_days must be at least 1` | Threshold too low | Set to 1 or higher |
| `expiration_threshold_days should not exceed 90` | Threshold too high | Set to 90 or lower |
| `Invalid key_type` | Bad key type | Use `rsa` or `ecdsa` |
| `Invalid rsa_key_size` | Bad RSA size | Use 2048, 3072, or 4096 |
| `Invalid elliptic_curve` | Bad curve | Use `secp256r1` or `secp384r1` |

### Authentication Errors

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `Failed to authenticate to Azure Key Vault` | Azure credentials missing | Run `az login` or configure service principal |
| `GitHub OIDC environment not detected` | Not in GitHub Actions | Add OIDC permissions to workflow or use local credentials |
| `GitHub OIDC detected but no role_arn configured` | Missing AWS role | Add `role_arn` to Route53 account config |
| `AWS credentials not configured` | No AWS auth available | Configure OIDC with role_arn or set AWS env vars |

### Certbot/DNS Errors

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `Certbot not found` | Certbot not installed | Run `pip install certbot` |
| `Certbot failed: [error]` | Certbot execution failed | Check DNS config, domain ownership, or certbot logs |
| `Certificate directory not found` | Certbot didn't create files | Verify domain is correct and DNS zone is configured |
| `No DNS zone configured for domain 'xxx.com'` | Domain not in config | Add domain's zone to dns_providers section |

### Certificate Operation Errors

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `Certificate not found` | Cert doesn't exist in vault | Verify certificate name |
| `Failed to import certificate` | Upload failed | Check Key Vault permissions |
| `OpenSSL not found` | OpenSSL not installed | Install OpenSSL |
| `PFX conversion failed` | Invalid cert files | Verify cert/key are valid PEM |

### Notification Errors

Notification errors are **logged but don't fail** the renewal process.

| Error Message | Cause | Solution |
|---------------|-------|----------|
| `SENDGRID_API_KEY not set` | Missing API key | Set SENDGRID_API_KEY env var |
| `SendGrid API error: 401` | Invalid API key | Verify API key is correct |
| `SendGrid API error: 403` | Sender not verified | Verify from_email in SendGrid |
| `TEAMS_WEBHOOK_URL environment variable not set` | Missing webhook URL | Set TEAMS_WEBHOOK_URL env var |
| `Teams webhook error: 4xx` | Invalid webhook | Verify webhook URL is valid |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All operations succeeded |
| 1 | One or more operations failed |
| 2 | Configuration error (fix config before retry) |

---

## Pre-Production Checklist

Before running in production, verify:

### Configuration
- [ ] At least one Azure Key Vault configured in `vaults`
- [ ] All vault URLs start with `https://`
- [ ] All vault names are alphanumeric with hyphens only
- [ ] `expiration_threshold_days` is between 1-90

### DNS Provider
- [ ] At least one DNS provider configured (Route53 or Azure DNS)
- [ ] All certificate domains exist in configured DNS zones
- [ ] Each Azure DNS zone has correct `resource_group` specified

### Authentication
- [ ] Azure authentication working (test: `az keyvault list`)
- [ ] Key Vault permissions granted (Certificates Officer role)
- [ ] DNS Zone permissions granted (DNS Zone Contributor role)
- [ ] If using Route53: AWS credentials or OIDC role configured

### Notifications (if enabled)
- [ ] `SENDGRID_API_KEY` environment variable set
- [ ] Sender email verified in SendGrid
- [ ] `TEAMS_WEBHOOK_URL` environment variable set
- [ ] Teams webhook is for a public channel

### Testing
- [ ] `--dry-run` completes without errors
- [ ] Certificates are discovered correctly
- [ ] DNS zones are matched to certificates
- [ ] Notifications are received (test with a failing cert or manual trigger)

### GitHub Actions (if using)
- [ ] `id-token: write` permission in workflow
- [ ] Repository variables set: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_SUBSCRIPTION_ID
- [ ] Repository secrets set: PFX_PASSWORD, SENDGRID_API_KEY, TEAMS_WEBHOOK_URL
- [ ] Azure OIDC federation configured
- [ ] AWS OIDC federation configured (if using Route53)

---

## Getting Help

- Check the [README.md](README.md) for technical documentation
- Review error messages in verbose mode: `--verbose`
- Check Certbot logs in the configured `certbot_logs_dir`
- For issues, open a ticket in the repository

---

## Notification Details

### What's Included in Notifications

Each notification (email or Teams) includes:
- **Vault Name**: Which Key Vault the certificate is in
- **Certificate Name**: Name of the certificate
- **Common Name (CN)**: Primary domain on the certificate
- **Subject Alternative Names (SAN)**: All domains covered
- **Expiry Date**:
  - For SUCCESS: New certificate expiry date
  - For FAILURE: Old certificate expiry date (still relevant)
- **Status**: SUCCESS or FAILED
- **Status Emoji**: ✅ (success) or ❌ (failure)
- **Failure Reason**: Error details if renewal failed

### Notification Title Format

```
<STATUS>: Let's Encrypt Certificate Auto Renewal Notification for <certificate_name>
```

Examples:
- `SUCCESS: Let's Encrypt Certificate Auto Renewal Notification for api-cert`
- `FAILED: Let's Encrypt Certificate Auto Renewal Notification for web-cert`
