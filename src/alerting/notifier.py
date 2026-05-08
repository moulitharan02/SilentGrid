"""
Notifier — nt-traffic-filter.
Dispatches alert notifications to configured external channels:
  • Slack webhook
  • SMTP e-mail
Add more channels by extending the _channels list.
"""

from __future__ import annotations

import smtplib
import textwrap
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Any, Dict, List

import requests

from src.config.config import (
    SLACK_WEBHOOK_URL,
    EMAIL_SMTP_HOST,
    EMAIL_SMTP_PORT,
    EMAIL_SENDER,
    EMAIL_PASSWORD,
    EMAIL_RECIPIENTS,
)
from src.utils.logger import get_logger

log = get_logger(__name__)


class Notifier:
    """Sends alerts to all configured notification channels."""

    def send(self, title: str, body: str, metadata: Dict[str, Any]) -> None:
        """
        Broadcast an alert to every active channel.

        Args:
            title:    Short alert title.
            body:     Alert message body.
            metadata: Key-value context attached to the alert.
        """
        channels = self._active_channels()
        if not channels:
            log.debug("No notification channels configured.")
            return

        for channel in channels:
            try:
                channel(title, body, metadata)
            except Exception as exc:
                log.error("Notification channel failed: %s", exc)

    # ── Channel registry ──────────────────────────────────────────────────────

    def _active_channels(self) -> List:
        channels = []
        if SLACK_WEBHOOK_URL:
            channels.append(self._slack)
        if EMAIL_SENDER and EMAIL_RECIPIENTS and EMAIL_RECIPIENTS != [""]:
            channels.append(self._email)
        return channels

    # ── Slack ─────────────────────────────────────────────────────────────────

    def _slack(self, title: str, body: str, metadata: Dict[str, Any]) -> None:
        fields = [
            {"type": "mrkdwn", "text": f"*{k}*\n{v}"}
            for k, v in metadata.items()
        ]
        payload = {
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": title, "emoji": True},
                },
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": body},
                },
                {"type": "section", "fields": fields},
            ]
        }
        resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        resp.raise_for_status()
        log.debug("Slack notification sent (HTTP %d)", resp.status_code)

    # ── E-mail ────────────────────────────────────────────────────────────────

    def _email(self, title: str, body: str, metadata: Dict[str, Any]) -> None:
        detail = "\n".join(f"  {k}: {v}" for k, v in metadata.items())
        full_body = textwrap.dedent(f"""\
            {body}

            Details:
            {detail}

            -- nt-traffic-filter
        """)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = title
        msg["From"]    = EMAIL_SENDER
        msg["To"]      = ", ".join(EMAIL_RECIPIENTS)
        msg.attach(MIMEText(full_body, "plain"))

        with smtplib.SMTP(EMAIL_SMTP_HOST, EMAIL_SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENTS, msg.as_string())

        log.debug("Email notification sent to %s", EMAIL_RECIPIENTS)
