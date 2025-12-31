# Azure Key Vault Certificate Renewal Automation

Automated SSL/TLS certificate renewal for Azure Key Vault using Certbot with DNS validation.

## How It Works

This solution uses **Certbot DNS plugins** which **automatically handle DNS record management**:

1. **Auto-Discovery**: Script scans all configured Key Vaults and discovers all certificates
2. **Let's Encrypt Filter**: Only renews certificates issued by Let's Encrypt (skips others)
3. **Domain Extraction**: Extracts domain names from certificate SANs (Subject Alternative Names)
4. **DNS Provider Auto-Detection**: Matches domains to configured DNS zones to determine which provider (AWS Route53 or Azure DNS) and which credentials to use
5. **AWS Authentication**: For Route53, assumes the IAM role specified in config via OIDC federation
6. **Certbot Renewal**: For each expiring cert, Certbot runs with the appropriate DNS plugin
7. **Automatic DNS**: The DNS plugin automatically:
   - Creates the `_acme-challenge` TXT record
   - Waits for DNS propagation
   - Completes Let's Encrypt validation
   - Cleans up the TXT record
8. **Upload to Key Vault**: Renewed certificate is converted to PFX and uploaded

**No manual certificate listing required** - all certificates are auto-discovered from Key Vaults.
**No manual DNS updates required** - the plugins handle everything.

## Features

- **Certificate Auto-Discovery**: Automatically finds all certificates in each vault
- **Let's Encrypt Verification**: Only renews certificates issued by Let's Encrypt
- **Ignore List**: Skip specific certificates per vault
- **Dual Execution Modes**: Automatic (scan all vaults) or Manual (specific certificate)
- **Multi-Vault Support**: Process multiple Azure Key Vaults in a single run
- **Multi-Account DNS**: Support for multiple AWS accounts and Azure subscriptions
- **AWS OIDC Authentication**: Secure authentication via GitHub OIDC federation (no static credentials)
- **Continue on Errors**: Process all certificates even if some fail
- **Dry-Run Mode**: Test without making actual changes
- **Colored Logging**: Clear, structured output with color-coded status
- **Notification System**: Email (SendGrid) and Microsoft Teams notifications for renewal events

## Project Structure

```
letsencrypt/
├── main.py                  # Entry point with argparse CLI
├── config.yaml              # Configuration file (YAML format)
├── requirements.txt         # Python dependencies
├── templates/               # Notification templates
│   ├── email_notification.html   # Email template (HTML)
│   └── teams_notification.json   # Teams Adaptive Card template
├── utils/
│   ├── __init__.py          # Package exports
│   ├── keyvault.py          # Azure Key Vault operations
│   ├── certbot.py           # Certbot renewal wrapper
│   ├── config_loader.py     # YAML config loading and validation
│   ├── logger.py            # Centralized structured logging
│   ├── helpers.py           # Common utility functions
│   └── notification.py      # Email (SendGrid) and Teams notifications

```

## Prerequisites

### System Requirements
- Python 3.8+
- OpenSSL (for PFX conversion)
- Certbot with DNS plugins

### Installation

```bash
# Clone the repository
git clone <repository-url>
cd letsencrypt

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# or: venv\Scripts\activate  # Windows

# Install dependencies
pip install -r requirements.txt
```

### Authentication (GitHub Actions with OIDC)

This solution uses **federated identity (OIDC)** for both AWS and Azure - no static secrets required.

#### Azure Setup

1. **Create an App Registration** with federated credentials for GitHub Actions:
   ```bash
   # Create app registration
   az ad app create --display-name "certbot-renewal"

   # Add federated credential for GitHub Actions
   az ad app federated-credential create \
       --id <app-id> \
       --parameters '{
         "name": "github-actions",
         "issuer": "https://token.actions.githubusercontent.com",
         "subject": "repo:<owner>/<repo>:ref:refs/heads/main",
         "audiences": ["api://AzureADTokenExchange"]
       }'
   ```

2. **Grant permissions**:
   - **Key Vault**: Assign "Key Vault Certificates Officer" role
   - **DNS Zone**: Assign "DNS Zone Contributor" role

3. **Environment variables** (set by `azure/login` action):
   ```bash
   AZURE_CLIENT_ID    # App registration client ID
   AZURE_TENANT_ID    # Azure AD tenant ID
   # No AZURE_CLIENT_SECRET needed with OIDC!
   ```

#### AWS Route53 Setup

The Python script handles AWS authentication automatically using GitHub's OIDC token and `AssumeRoleWithWebIdentity`. No `aws-actions/configure-aws-credentials` action needed.

1. **Create GitHub OIDC Identity Provider** in AWS (one-time per account):
   ```bash
   aws iam create-open-id-connect-provider \
       --url https://token.actions.githubusercontent.com \
       --client-id-list sts.amazonaws.com \
       --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
   ```

2. **Create an IAM Role** with trust policy for GitHub OIDC:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {
         "Federated": "arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com"
       },
       "Action": "sts:AssumeRoleWithWebIdentity",
       "Condition": {
         "StringEquals": {
           "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
         },
         "StringLike": {
           "token.actions.githubusercontent.com:sub": "repo:<owner>/<repo>:*"
         }
       }
     }]
   }
   ```

3. **Attach IAM policy** with Route53 permissions:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Action": [
         "route53:GetChange",
         "route53:ChangeResourceRecordSets",
         "route53:ListHostedZones"
       ],
       "Resource": "*"
     }]
   }
   ```

4. **Configure role_arn in config.yaml** (the script uses this to assume the role):
   ```yaml
   dns_providers:
     route53:
       accounts:
         "123456789012":
           hosted_zones:
             - "example.com"
           role_arn: "arn:aws:iam::123456789012:role/CertbotRoute53Role"
           # region: "eu-west-1"  # Optional - defaults to eu-west-1
   ```

   **Region priority** (highest to lowest):
   - `--aws-region` command line argument
   - `AWS_DEFAULT_REGION` environment variable
   - `region` in config.yaml per-account
   - Default: `eu-west-1`

**How it works:**
1. Script detects GitHub Actions environment (`ACTIONS_ID_TOKEN_REQUEST_URL`)
2. Fetches OIDC token from GitHub with audience `sts.amazonaws.com`
3. Calls `AssumeRoleWithWebIdentity` with the role_arn from config.yaml
4. Uses temporary credentials for Route53 DNS operations

## Configuration

Copy and customize the example configuration:

```bash
cp config.yaml config.local.yaml
# Edit config.local.yaml with your settings
```

### Configuration Schema (YAML)

```yaml
# Global settings
settings:
  expiration_threshold_days: 10
  letsencrypt_email: "devops@example.com"  # Optional - recommended for notifications
  continue_on_error: true
  cleanup_after_upload: true
  certbot_work_dir: "/tmp/certbot"
  certbot_logs_dir: "/tmp/certbot-logs"
  certbot_config_dir: "/tmp/certbot-config"
  # Certificate key configuration
  key_type: "rsa"           # "rsa" or "ecdsa" (default: rsa)
  rsa_key_size: 2048        # 2048, 3072, or 4096 (default: 2048)
  elliptic_curve: "secp384r1"  # secp256r1 or secp384r1 (default: secp384r1)

# DNS Provider configurations
# DNS provider is auto-detected by matching certificate domains to these zones
dns_providers:
  route53:
    accounts:
      "123456789012":
        hosted_zones:
          - "example.com"
          - "example.org"
        # IAM role to assume for this account (for OIDC/cross-account)
        role_arn: "arn:aws:iam::123456789012:role/CertbotRoute53Role"
        region: "us-east-1"

  azure:
    subscriptions:
      "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee":
        zones:
          - zone: "contoso.com"
            resource_group: "dns-rg-contoso"
          - zone: "fabrikam.com"
            resource_group: "dns-rg-fabrikam"

# Azure Key Vaults to scan (all certificates discovered automatically)
# DNS provider is auto-detected based on certificate domains
vaults:
  - name: "prod-keyvault"
    url: "https://prod-keyvault.vault.azure.net/"
    ignore_certificates:
      - "legacy-cert"
      - "imported-cert"

  - name: "staging-keyvault"
    url: "https://staging-keyvault.vault.azure.net/"
    ignore_certificates: []
```

### Configuration Sections

#### settings

| Field | Default | Description |
|-------|---------|-------------|
| `expiration_threshold_days` | 10 | Days before expiry to trigger renewal |
| `letsencrypt_email` | `""` (empty) | Email for Let's Encrypt notifications (optional) |
| `continue_on_error` | true | Continue processing if a certificate fails |
| `cleanup_after_upload` | true | Delete local cert files after upload |
| `key_type` | `rsa` | Certificate key type: `rsa` or `ecdsa` |
| `rsa_key_size` | 2048 | RSA key size: 2048, 3072, or 4096 (when key_type is rsa) |
| `elliptic_curve` | `secp384r1` | ECDSA curve: `secp256r1` or `secp384r1` (when key_type is ecdsa) |

**Note on `letsencrypt_email`:** This field is optional. If left empty or not provided, the script will register with Let's Encrypt without an email address using `--register-unsafely-without-email`. While this works, it's recommended to provide an email to receive important notifications about certificate expiration and renewal issues.

#### dns_providers.route53.accounts

| Field | Required | Description |
|-------|----------|-------------|
| `hosted_zones` | Yes | List of DNS zones in this account |
| `role_arn` | No | IAM role to assume for this account |
| `region` | No | AWS region (default: us-east-1) |

#### dns_providers.azure.subscriptions

| Field | Required | Description |
|-------|----------|-------------|
| `zones` | Yes | List of zone configurations (see below) |

Each zone entry:

| Field | Required | Description |
|-------|----------|-------------|
| `zone` | Yes | DNS zone name (e.g., "example.com") |
| `resource_group` | Yes | Resource group containing this DNS zone |

#### vaults

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Vault name (for logging) |
| `url` | Yes | Full URL to the Key Vault |
| `include_certificates` | No | List of certificate names to process (whitelist mode) |
| `ignore_certificates` | No | List of certificate names to always skip |

**Certificate Selection Rules** (in order of precedence):
1. `ignore_certificates` **always takes precedence** - these certificates are NEVER processed
2. If `include_certificates` is empty or not specified - process ALL certificates (minus ignored)
3. If `include_certificates` contains entries - ONLY process those certificates (minus ignored)

**Example configurations:**

```yaml
vaults:
  # Whitelist mode: only process specific certificates
  - name: "prod-keyvault"
    url: "https://prod-keyvault.vault.azure.net/"
    include_certificates:
      - "api-cert"
      - "web-cert"
    ignore_certificates:
      - "legacy-cert"  # Still ignored even if added to include_certificates

  # Default mode: process all certificates except ignored
  - name: "staging-keyvault"
    url: "https://staging-keyvault.vault.azure.net/"
    ignore_certificates:
      - "test-cert"
```

**Note**: DNS provider is auto-detected by matching certificate domains against the zones configured in `dns_providers`. This allows a single vault to contain certificates using different DNS providers.

#### notifications

Configure notification channels for certificate renewal events. Notifications are sent **per-certificate** for both success and failure events.

| Field | Type | Description |
|-------|------|-------------|
| `email.enabled` | bool | Enable email notifications via SendGrid |
| `email.from_email` | string | Sender email address (must be verified in SendGrid) |
| `email.to_emails` | list | List of recipient email addresses |
| `email.template_path` | string | Optional: Path to custom HTML email template |
| `teams.enabled` | bool | Enable Microsoft Teams notifications |
| `teams.webhook_url` | string | Teams incoming webhook URL (or use `TEAMS_WEBHOOK_URL` env var) |
| `teams.template_path` | string | Optional: Path to custom JSON Adaptive Card template |

**Example configuration:**

```yaml
notifications:
  email:
    enabled: true
    from_email: "certificates@example.com"
    to_emails:
      - "devops@example.com"
      - "security@example.com"
    # template_path: "templates/email_notification.html"  # Optional

  teams:
    enabled: true
    webhook_url: "${TEAMS_WEBHOOK_URL}"  # Use environment variable
    # template_path: "templates/teams_notification.json"  # Optional
```

**Notification behavior:**
- Notifications are sent for **every certificate processed** (success or failure)
- Notification failures are **logged but do not crash** the main workflow
- Both channels can be enabled simultaneously
- Custom templates support variable substitution (`{{vault_name}}`, `{{certificate_name}}`, etc.)

**Email notification details include:**
- Vault name
- Certificate name
- Common Name (CN)
- Subject Alternative Names (SAN)
- Expiry date
- Renewal status (SUCCESS/FAILED)
- Failure reason (if applicable)

## Usage

### Automatic Mode (Recommended)

Scan all configured vaults and renew expiring certificates:

```bash
# Basic usage
python main.py --auto

# With config file
python main.py --auto --config config.yaml

# Dry run (no changes)
python main.py --auto --dry-run

# Verbose logging
python main.py --auto --verbose

# Override threshold
python main.py --auto --threshold 14
```

### Manual Renewal Mode

Renew a specific certificate:

```bash
python main.py \
    --vault-name prod-keyvault \
    --certificate-name my-cert
```

### Create Mode

Create a new certificate and upload to Key Vault:

```bash
python main.py --task create \
    --san "example.com,www.example.com,api.example.com" \
    --vault-url https://my-keyvault.vault.azure.net/ \
    --subscription aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
    --cert-name my-new-cert

# Dry run (test without making changes)
python main.py --task create \
    --san "example.com" \
    --vault-url https://my-keyvault.vault.azure.net/ \
    --subscription aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee \
    --cert-name my-new-cert \
    --dry-run
```

**Create mode requirements:**
- `--san`: Comma-separated list of domain names (SANs) for the certificate
- `--vault-url`: Full URL of the target Key Vault
- `--subscription`: Azure subscription ID where the Key Vault resides
- `--cert-name`: Name for the certificate in Key Vault
- The domain(s) must be configured in `dns_providers` section of config.yaml

### Command-Line Options

| Option | Description |
|--------|-------------|
| `--task` | Task type: `create` or `renew` (default: renew) |
| `--auto` | Automatic mode: scan all vaults |
| `--vault-name` | Manual renewal mode: vault name |
| `--certificate-name, --cert-name` | Certificate name (for create or manual renew) |
| `--san` | Create mode: comma-separated SANs |
| `--vault-url` | Create mode: Key Vault URL |
| `--subscription` | Create mode: Azure subscription ID |
| `--config` | Path to config file (default: config.yaml) |
| `--dry-run` | Test mode, no actual changes |
| `--threshold` | Override expiration threshold (days) |
| `--pfx-password` | Password for PFX (falls back to PFX_PASSWORD env var) |
| `--key-type` | Certificate key type: rsa or ecdsa (overrides config) |
| `--rsa-key-size` | RSA key size: 2048, 3072, or 4096 (overrides config) |
| `--elliptic-curve` | ECDSA curve: secp256r1 or secp384r1 (overrides config) |
| `--verbose, -v` | Enable debug logging |
| `--no-color` | Disable colored output |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success (all certificates processed) |
| 1 | Failure (one or more renewals failed) |
| 2 | Configuration error |

## Certificate Filtering Logic

The script applies the following filters when processing certificates:

1. **Ignore List**: Certificates in `ignore_certificates` are skipped
2. **Issuer Check**: Only Let's Encrypt certificates are renewed (others are skipped with a log message)
3. **Expiration Check**: Only certificates expiring within `expiration_threshold_days` are renewed

## GitHub Actions Examples

### Automatic Certificate Renewal (Scheduled)

Example workflow for scheduled certificate renewal using OIDC federation (no static secrets):

```yaml
name: Certificate Renewal

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
  workflow_dispatch:

permissions:
  id-token: write    # Required for OIDC (both AWS and Azure)
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
          PFX_PASSWORD: ${{ secrets.PFX_PASSWORD }}  # Optional: encrypt PFX with password
          SENDGRID_API_KEY: ${{ secrets.SENDGRID_API_KEY }}  # Optional: for email notifications
          TEAMS_WEBHOOK_URL: ${{ secrets.TEAMS_WEBHOOK_URL }}  # Optional: for Teams notifications
        run: python main.py --auto --verbose
```

### Create New Certificate (Manual Trigger)

Example workflow for creating new certificates with user input:

```yaml
name: Create Certificate

on:
  workflow_dispatch:
    inputs:
      san:
        description: 'Comma-separated list of domains (e.g., example.com,www.example.com)'
        required: true
        type: string
      vault_url:
        description: 'Key Vault URL (e.g., https://my-vault.vault.azure.net/)'
        required: true
        type: string
      subscription:
        description: 'Azure Subscription ID for the Key Vault'
        required: true
        type: string
      cert_name:
        description: 'Certificate name in Key Vault'
        required: true
        type: string

permissions:
  id-token: write    # Required for OIDC (both AWS and Azure)
  contents: read

jobs:
  create:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ inputs.subscription }}

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Create certificate
        env:
          AZURE_CLIENT_ID: ${{ vars.AZURE_CLIENT_ID }}
          AZURE_TENANT_ID: ${{ vars.AZURE_TENANT_ID }}
          PFX_PASSWORD: ${{ secrets.PFX_PASSWORD }}  # Optional: encrypt PFX with password
        run: |
          python main.py --task create \
            --san "${{ inputs.san }}" \
            --vault-url "${{ inputs.vault_url }}" \
            --subscription "${{ inputs.subscription }}" \
            --cert-name "${{ inputs.cert_name }}" \
            --verbose
```

**Key Points:**
- **No `aws-actions/configure-aws-credentials` needed** - AWS authentication is handled in Python code
- AWS role ARN is specified per-account in `config.yaml` under `dns_providers.route53.accounts`
- The script uses `AssumeRoleWithWebIdentity` to assume the role using GitHub's OIDC token
- Store `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, and `AZURE_SUBSCRIPTION_ID` as repository variables (not secrets)
- The create workflow uses `workflow_dispatch` with inputs for manual triggering from GitHub UI

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                            │
│                        (main.py)                             │
│         - Argument parsing (--auto, --vault-name, etc.)     │
│         - Mode selection (automatic vs manual)              │
├─────────────────────────────────────────────────────────────┤
│                    Processing Logic                          │
│         - Certificate filtering (LE issuer, expiry, ignore) │
│         - Result aggregation and summary                    │
├─────────────────────────────┬───────────────────────────────┤
│       keyvault.py           │         certbot.py            │
│  - List all certs in vault  │  - Run renewal                │
│  - Get certificate details  │  - Convert to PFX             │
│  - Upload renewed cert      │  - AWS/Azure credentials      │
├─────────────────────────────┴───────────────────────────────┤
│                    Utilities                                 │
│    config_loader.py  │  logger.py  │  helpers.py            │
│    - YAML parsing    │  - Logging  │  - Date helpers        │
│    - Validation      │  - Colors   │  - LE issuer check     │
└─────────────────────────────────────────────────────────────┘
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `AZURE_CLIENT_ID` | Yes | Azure AD application (client) ID |
| `AZURE_TENANT_ID` | Yes | Azure AD tenant ID |
| `AZURE_SUBSCRIPTION_ID` | For renewal | Default Azure subscription ID |
| `PFX_PASSWORD` | No | Password for PFX certificate encryption (see below) |
| `SENDGRID_API_KEY` | For email | SendGrid API key (required if email notifications enabled) |
| `TEAMS_WEBHOOK_URL` | For Teams | Microsoft Teams incoming webhook URL (alternative to config) |

### PFX Password Support

By default, certificates are converted to PFX format without a password. To encrypt the PFX file with a password, use one of the following methods (in order of priority):

1. **Command-line argument** `--pfx-password` (highest priority)
2. **Environment variable** `PFX_PASSWORD`
3. **Empty password** (default if neither is set)

The same password is used for both PFX creation and Key Vault import.

**Local usage (command-line):**
```bash
python main.py --auto --pfx-password "your-secure-password"
```

**Local usage (environment variable):**
```bash
export PFX_PASSWORD="your-secure-password"
python main.py --auto
```

**GitHub Actions:**
1. Add `PFX_PASSWORD` as a repository secret
2. Pass it to the workflow step:
```yaml
- name: Run certificate renewal
  env:
    AZURE_CLIENT_ID: ${{ vars.AZURE_CLIENT_ID }}
    AZURE_TENANT_ID: ${{ vars.AZURE_TENANT_ID }}
    PFX_PASSWORD: ${{ secrets.PFX_PASSWORD }}
  run: python main.py --auto --verbose
```

## Security Best Practices

- **Never commit credentials** to version control
- Use **GitHub OIDC** instead of long-lived AWS access keys
- Use **environment variables** for Azure credentials
- Restrict Service Principal permissions (Principle of Least Privilege)
- Enable **Key Vault soft delete** and purge protection
- Use **Managed Identity** when running on Azure resources
- Set file permissions: `chmod 600` for credential files
- Rotate secrets regularly (every 90 days recommended)
- **No static AWS credentials** - use OIDC or role assumption
- **Use PFX_PASSWORD** to encrypt certificate private keys in transit

## Troubleshooting

### Common Issues

**Authentication failed to Azure Key Vault**
- Verify environment variables are set correctly
- Check Service Principal has correct permissions
- Try `az login` for interactive testing

**No certificates found for renewal**
- Check expiration threshold setting
- Verify Key Vault contains Let's Encrypt certificates
- Use `--verbose` to see all certificate statuses

**Certificate skipped - not Let's Encrypt**
- This is expected for non-LE certificates
- Only Let's Encrypt certificates are auto-renewed
- Add to `ignore_certificates` to suppress the log message

**Domain not matched to any DNS zone**
- Add the domain's zone to `dns_providers` configuration
- Check for typos in zone names
- Verify the zone matches the certificate's domains

**AWS role assumption failed**
- Verify the role ARN is correct
- Check trust policy allows your identity
- Ensure OIDC provider is configured (for GitHub Actions)

**Certbot not found**
- Install with: `pip install certbot certbot-dns-route53 certbot-dns-azure`

**DNS validation timeout**
- Verify DNS provider credentials
- Check DNS zone configuration
- Ensure outbound HTTPS (port 443) is allowed

**Permission denied uploading to Key Vault**
- Grant 'Key Vault Administrator' or 'Key Vault Certificates Officer' role

**Email notifications not being sent**
- Verify `SENDGRID_API_KEY` environment variable is set
- Ensure the `from_email` address is verified in SendGrid
- Check that `email.enabled` is `true` in config
- Check logs for SendGrid API error messages

**Teams notifications not being sent**
- Verify the webhook URL is correct and active
- Ensure `TEAMS_WEBHOOK_URL` env var or `teams.webhook_url` config is set
- Check that `teams.enabled` is `true` in config
- Teams webhook URLs expire if the connector is removed from the channel

**Notifications sent but content is wrong**
- If using custom templates, verify variable names match: `{{vault_name}}`, `{{certificate_name}}`, `{{common_name}}`, `{{san_list}}`, `{{expiry_date}}`, `{{status}}`, `{{failure_reason}}`
- Check template file path is correct relative to the project root

## License

MIT License
