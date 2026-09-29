"""
Alert Notification Manager
===========================
Sends email/Slack notifications for critical alerts.
Configure SMTP settings in config.yaml
"""

import smtplib
import yaml
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, Optional
import json
import http.client as httplib


class AlertManager:
    """Manages alert notifications via email and Slack."""

    def __init__(self, config_path: str = "config.yaml"):
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        self.notify_config = config.get("notifications", {})
        self.email_enabled = self.notify_config.get("email_enabled", False)
        self.slack_enabled = self.notify_config.get("slack_enabled", False)
        self.min_severity = self.notify_config.get("min_severity", "high")
        self.cooldown_seconds = self.notify_config.get("cooldown_seconds", 60)

        self.last_notification: Dict[str, float] = {}

    def should_notify(self, severity: str, attack_type: str) -> bool:
        """Check if notification should be sent based on severity and cooldown."""
        severity_levels = {"low": 0, "medium": 1, "high": 2}
        if severity_levels.get(severity, 0) < severity_levels.get(self.min_severity, 2):
            return False

        # Cooldown check
        key = f"{severity}_{attack_type}"
        now = datetime.now().timestamp()
        if key in self.last_notification:
            if now - self.last_notification[key] < self.cooldown_seconds:
                return False

        self.last_notification[key] = now
        return True

    def send_email(self, alert_data: Dict) -> bool:
        """Send email notification for critical alerts."""
        if not self.email_enabled:
            return False

        try:
            smtp_config = self.notify_config.get("smtp", {})

            msg = MIMEMultipart()
            msg["From"] = smtp_config.get("from_email", "nids@localhost")
            msg["To"] = smtp_config.get("to_email", "admin@localhost")
            msg["Subject"] = f"[SOC-NIDS] {alert_data.get('severity','').upper()} Alert: {alert_data.get('attack_type','Unknown')}"

            body = f"""
            ╔══════════════════════════════════════╗
            ║     SOC-NIDS THREAT ALERT           ║
            ╚══════════════════════════════════════╝

            Time:       {alert_data.get('timestamp', datetime.now().isoformat())}
            Attack:     {alert_data.get('attack_type', 'Unknown')}
            Severity:   {alert_data.get('severity', 'low').upper()}
            Score:      {alert_data.get('final_score', 0):.2%}
            Source:     {alert_data.get('source_ip', 'N/A')}
            Destination:{alert_data.get('destination_ip', 'N/A')}

            Rule Score: {alert_data.get('rule_score', 0):.2%}
            ML Score:   {alert_data.get('ml_score', 0):.2%}

            Summary: {alert_data.get('packet_summary', 'No details')}

            ---
            SOC-NIDS // Threat Command
            """

            msg.attach(MIMEText(body, "plain"))

            server = smtplib.SMTP(smtp_config.get("host", "localhost"), smtp_config.get("port", 587))
            server.starttls()
            server.login(smtp_config.get("username", ""), smtp_config.get("password", ""))
            server.send_message(msg)
            server.quit()

            print(f"[AlertManager] Email sent: {alert_data.get('attack_type')}")
            return True

        except Exception as e:
            print(f"[AlertManager] Email failed: {e}")
            return False

    def send_slack(self, alert_data: Dict) -> bool:
        """Send Slack webhook notification."""
        if not self.slack_enabled:
            return False

        try:
            webhook_url = self.notify_config.get("slack_webhook_url", "")
            if not webhook_url:
                return False

            severity_emoji = {"high": "🔴", "medium": "🟡", "low": "🟢"}
            emoji = severity_emoji.get(alert_data.get("severity", "low"), "⚪")

            payload = {
                "text": f"{emoji} *SOC-NIDS Alert*",
                "attachments": [{
                    "color": "#FF3355" if alert_data.get("severity") == "high" else "#FFA502" if alert_data.get("severity") == "medium" else "#10B981",
                    "fields": [
                        {"title": "Attack Type", "value": alert_data.get("attack_type", "Unknown"), "short": True},
                        {"title": "Severity", "value": alert_data.get("severity", "low").upper(), "short": True},
                        {"title": "Score", "value": f"{alert_data.get('final_score', 0):.2%}", "short": True},
                        {"title": "Source", "value": alert_data.get("source_ip", "N/A"), "short": True},
                        {"title": "Summary", "value": alert_data.get("packet_summary", "No details"), "short": False},
                    ]
                }]
            }

            conn = httplib.HTTPSConnection("hooks.slack.com")
            conn.request("POST", webhook_url.replace("https://hooks.slack.com", ""),
                        body=json.dumps(payload),
                        headers={"Content-Type": "application/json"})
            conn.getresponse()
            conn.close()

            print(f"[AlertManager] Slack sent: {alert_data.get('attack_type')}")
            return True

        except Exception as e:
            print(f"[AlertManager] Slack failed: {e}")
            return False

    def notify(self, alert_data: Dict) -> bool:
        """Send all configured notifications for an alert."""
        if not self.should_notify(alert_data.get("severity", "low"), alert_data.get("attack_type", "")):
            return False

        email_sent = self.send_email(alert_data)
        slack_sent = self.send_slack(alert_data)

        return email_sent or slack_sent
