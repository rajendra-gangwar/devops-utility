"""
Notification system for certificate renewal events.

Supports multiple notification channels:
- Email via SendGrid API
- Microsoft Teams via incoming webhook
"""

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import List, Optional, TYPE_CHECKING

import requests

from .logger import get_logger

if TYPE_CHECKING:
    from .config_loader import NotificationsConfig, EmailNotificationConfig, TeamsNotificationConfig


@dataclass
class NotificationContext:
    """Context data for a notification."""
    vault_name: str
    certificate_name: str
    common_name: str
    san_list: List[str]
    expiry_date: Optional[datetime]
    status: str  # "SUCCESS" or "FAILED"
    failure_reason: Optional[str] = None


class NotificationSender(ABC):
    """Abstract base class for notification senders."""

    @abstractmethod
    def send(self, context: NotificationContext) -> bool:
        """
        Send a notification.

        Args:
            context: Notification context with certificate details

        Returns:
            True if notification was sent successfully, False otherwise
        """
        pass


class SendGridNotifier(NotificationSender):
    """Send email notifications via SendGrid API."""

    def __init__(self, config: "EmailNotificationConfig"):
        self.config = config
        self.api_key = os.environ.get("SENDGRID_API_KEY", "")
        self.logger = get_logger()
        self._template: Optional[str] = None

    def _get_template_path(self) -> Path:
        """Get the path to the email template file."""
        # Look for template relative to this file's directory
        utils_dir = Path(__file__).parent
        project_root = utils_dir.parent
        return project_root / "templates" / "email_notification.html"

    def _load_template(self) -> str:
        """Load the email template from file."""
        if self._template is not None:
            return self._template

        template_path = self._get_template_path()
        if template_path.exists():
            with open(template_path, "r") as f:
                self._template = f.read()
        else:
            # Fallback to inline template if file not found
            self.logger.warning(f"Email template not found at {template_path}, using default")
            self._template = self._get_default_template()

        return self._template

    def _get_default_template(self) -> str:
        """Return a default email template."""
        return """<!DOCTYPE html>
<html>
<head>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { padding: 10px; border-radius: 5px; margin-bottom: 20px; }
        .success { background-color: #d4edda; color: #155724; }
        .failed { background-color: #f8d7da; color: #721c24; }
        table { border-collapse: collapse; width: 100%; max-width: 600px; }
        td { padding: 8px; border: 1px solid #ddd; }
        td:first-child { font-weight: bold; background-color: #f5f5f5; width: 150px; }
        .failure-reason { color: #721c24; }
    </style>
</head>
<body>
    <div class="header {{status_class}}">
        <h2>Certificate Renewal {{status}}</h2>
    </div>
    <table>
        <tr><td>Vault</td><td>{{vault_name}}</td></tr>
        <tr><td>Certificate</td><td>{{certificate_name}}</td></tr>
        <tr><td>Common Name</td><td>{{common_name}}</td></tr>
        <tr><td>SANs</td><td>{{san_list}}</td></tr>
        <tr><td>Expiry Date</td><td>{{expiry_date}}</td></tr>
        <tr><td>Status</td><td>{{status}}</td></tr>
        {{failure_row}}
    </table>
</body>
</html>"""

    def _render_template(self, context: NotificationContext) -> str:
        """Render the email template with context values."""
        template = self._load_template()

        # Format expiry date
        expiry_str = context.expiry_date.strftime("%Y-%m-%d %H:%M UTC") if context.expiry_date else "N/A"

        # Format SAN list
        san_str = ", ".join(context.san_list) if context.san_list else "N/A"

        # Status styling for email
        if context.status == "SUCCESS":
            status_emoji = "&#x2705;"  # Green checkmark
            border_color = "#28a745"
            header_bg_color = "#28a745"
            status_bg_color = "#d4edda"
            status_text_color = "#155724"
        else:
            status_emoji = "&#x274C;"  # Red X
            border_color = "#dc3545"
            header_bg_color = "#dc3545"
            status_bg_color = "#f8d7da"
            status_text_color = "#721c24"

        # Failure section (only if failed) - using table-based layout for email compatibility
        failure_section = ""
        if context.failure_reason:
            failure_section = f'''<table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="margin-bottom: 15px;">
                <tr>
                    <td style="padding: 20px; background-color: #fff3f3; border-radius: 6px; border-left: 4px solid #dc3545;">
                        <span style="display: block; font-weight: 600; color: #721c24; font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px;">Failure Reason</span>
                        <span style="color: #721c24; font-family: Courier New, monospace; font-size: 14px;">{context.failure_reason}</span>
                    </td>
                </tr>
            </table>'''

        # Replace placeholders
        html = template.replace("{{vault_name}}", context.vault_name)
        html = html.replace("{{certificate_name}}", context.certificate_name)
        html = html.replace("{{common_name}}", context.common_name)
        html = html.replace("{{san_list}}", san_str)
        html = html.replace("{{expiry_date}}", expiry_str)
        html = html.replace("{{status}}", context.status)
        html = html.replace("{{status_emoji}}", status_emoji)
        html = html.replace("{{border_color}}", border_color)
        html = html.replace("{{header_bg_color}}", header_bg_color)
        html = html.replace("{{status_bg_color}}", status_bg_color)
        html = html.replace("{{status_text_color}}", status_text_color)
        html = html.replace("{{failure_section}}", failure_section)
        html = html.replace("{{failure_reason}}", context.failure_reason or "")

        return html

    def send(self, context: NotificationContext) -> bool:
        """Send email notification via SendGrid."""
        if not self.api_key:
            self.logger.warning("SENDGRID_API_KEY not set, skipping email notification")
            return False

        if not self.config.from_email:
            self.logger.warning("Email from_email not configured, skipping email notification")
            return False

        if not self.config.to_emails:
            self.logger.warning("Email to_emails not configured, skipping email notification")
            return False

        try:
            html_content = self._render_template(context)
            subject = f"{context.status}: Let's Encrypt Certificate Auto Renewal Notification for {context.certificate_name}"

            # Build SendGrid API request
            payload = {
                "personalizations": [
                    {
                        "to": [{"email": email} for email in self.config.to_emails]
                    }
                ],
                "from": {"email": self.config.from_email},
                "subject": subject,
                "content": [
                    {
                        "type": "text/html",
                        "value": html_content
                    }
                ]
            }

            response = requests.post(
                "https://api.sendgrid.com/v3/mail/send",
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json"
                },
                timeout=30
            )

            if response.status_code in (200, 202):
                self.logger.info(f"Email notification sent for {context.certificate_name}")
                return True
            else:
                self.logger.error(
                    f"SendGrid API error: {response.status_code} - {response.text}"
                )
                return False

        except requests.RequestException as e:
            self.logger.error(f"Failed to send email notification: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending email: {e}")
            return False


class TeamsWebhookNotifier(NotificationSender):
    """Send notifications to Microsoft Teams via incoming webhook."""

    def __init__(self, config: "TeamsNotificationConfig"):
        self.config = config
        self.logger = get_logger()
        self._template: Optional[dict] = None

    def _get_template_path(self) -> Path:
        """Get the path to the Teams template file."""
        utils_dir = Path(__file__).parent
        project_root = utils_dir.parent
        return project_root / "templates" / "teams_notification.json"

    def _load_template(self) -> dict:
        """Load the Teams message template from file."""
        if self._template is not None:
            return self._template

        template_path = self._get_template_path()
        if template_path.exists():
            with open(template_path, "r") as f:
                self._template = json.load(f)
        else:
            self.logger.warning(f"Teams template not found at {template_path}, using default")
            self._template = self._get_default_template()

        return self._template

    def _get_default_template(self) -> dict:
        """Return a default Teams message card template."""
        return {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "{{theme_color}}",
            "summary": "Certificate Renewal {{status}}",
            "sections": [
                {
                    "activityTitle": "Certificate Renewal {{status}}",
                    "facts": [
                        {"name": "Vault", "value": "{{vault_name}}"},
                        {"name": "Certificate", "value": "{{certificate_name}}"},
                        {"name": "Common Name", "value": "{{common_name}}"},
                        {"name": "SANs", "value": "{{san_list}}"},
                        {"name": "Expiry Date", "value": "{{expiry_date}}"},
                        {"name": "Status", "value": "{{status}}"}
                    ],
                    "markdown": True
                }
            ]
        }

    def _render_template(self, context: NotificationContext) -> dict:
        """Render the Teams template with context values."""
        # Deep copy template to avoid mutation
        template = json.loads(json.dumps(self._load_template()))

        # Format values
        expiry_str = context.expiry_date.strftime("%Y-%m-%d %H:%M UTC") if context.expiry_date else "N/A"
        san_str = ", ".join(context.san_list) if context.san_list else "N/A"
        theme_color = "28a745" if context.status == "SUCCESS" else "dc3545"
        status_emoji = "\u2705" if context.status == "SUCCESS" else "\u274C"  # Checkmark or X
        failure_reason = context.failure_reason or "N/A"

        # Replace in JSON structure
        def replace_placeholders(obj):
            if isinstance(obj, str):
                obj = obj.replace("{{vault_name}}", context.vault_name)
                obj = obj.replace("{{certificate_name}}", context.certificate_name)
                obj = obj.replace("{{common_name}}", context.common_name)
                obj = obj.replace("{{san_list}}", san_str)
                obj = obj.replace("{{expiry_date}}", expiry_str)
                obj = obj.replace("{{status}}", context.status)
                obj = obj.replace("{{theme_color}}", theme_color)
                obj = obj.replace("{{status_emoji}}", status_emoji)
                obj = obj.replace("{{failure_reason}}", failure_reason)
                return obj
            elif isinstance(obj, dict):
                return {k: replace_placeholders(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [replace_placeholders(item) for item in obj]
            return obj

        payload = replace_placeholders(template)

        return payload

    def send(self, context: NotificationContext) -> bool:
        """Send notification to Teams via webhook."""
        # Get webhook URL from environment variable
        webhook_url = os.environ.get("TEAMS_WEBHOOK_URL", "")
        if not webhook_url:
            self.logger.warning("TEAMS_WEBHOOK_URL environment variable not set, skipping Teams notification")
            return False

        try:
            payload = self._render_template(context)

            response = requests.post(
                webhook_url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=30
            )

            # Teams webhook returns 200 with "1" on success
            if response.status_code == 200:
                self.logger.info(f"Teams notification sent for {context.certificate_name}")
                return True
            else:
                self.logger.error(
                    f"Teams webhook error: {response.status_code} - {response.text}"
                )
                return False

        except requests.RequestException as e:
            self.logger.error(f"Failed to send Teams notification: {e}")
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error sending Teams notification: {e}")
            return False


class NotificationManager:
    """
    Manages all notification channels.

    Orchestrates sending notifications through all enabled channels.
    Ensures notification failures don't crash the main workflow.
    """

    def __init__(self, config: "NotificationsConfig"):
        self.config = config
        self.logger = get_logger()
        self.notifiers: List[NotificationSender] = []

        # Initialize enabled notifiers
        if config.email.enabled:
            self.notifiers.append(SendGridNotifier(config.email))
            self.logger.info("Email notifications enabled")

        if config.teams.enabled:
            self.notifiers.append(TeamsWebhookNotifier(config.teams))
            self.logger.info("Teams notifications enabled")

        if not self.notifiers:
            self.logger.info("No notification channels enabled")

    def notify(self, context: NotificationContext) -> None:
        """
        Send notifications through all enabled channels.

        This method never raises exceptions - all errors are logged
        but don't affect the main workflow.

        Args:
            context: Notification context with certificate details
        """
        if not self.notifiers:
            return

        self.logger.debug(
            f"Sending notifications for {context.certificate_name} ({context.status})"
        )

        for notifier in self.notifiers:
            try:
                notifier.send(context)
            except Exception as e:
                # Log but never crash - notifications are non-blocking
                notifier_name = type(notifier).__name__
                self.logger.error(
                    f"Notification failed ({notifier_name}): {e}"
                )

    def is_enabled(self) -> bool:
        """Check if any notification channel is enabled."""
        return len(self.notifiers) > 0
