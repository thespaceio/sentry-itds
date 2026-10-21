"""Alerting for newly opened cases.

Sends one message per *new* case (re-runs that only update an existing case
stay quiet). Messages carry the pseudonym, the risk score, the top findings and
a link to the dashboard: never a name, department or anything that would
re-identify the person, because chat channels and inboxes are not access
controlled the way Sentry is.

Configured entirely through environment variables:

    ITDS_ALERT_WEBHOOK_URL    generic JSON POST (SOAR, SIEM, ticketing)
    ITDS_ALERT_SLACK_WEBHOOK  Slack incoming webhook
    ITDS_ALERT_SMTP_HOST      email, with ITDS_ALERT_SMTP_PORT (587),
                              ITDS_ALERT_SMTP_USER, ITDS_ALERT_SMTP_PASSWORD,
                              ITDS_ALERT_EMAIL_FROM, ITDS_ALERT_EMAIL_TO (comma separated)
    ITDS_DASHBOARD_URL        base URL used for links (default http://localhost:8000)

No third-party dependencies: urllib and smtplib from the standard library.
"""

from __future__ import annotations

import json
import os
import smtplib
import ssl
import urllib.request
from dataclasses import dataclass, field
from email.message import EmailMessage

TIMEOUT = 10


def case_payload(case, dashboard_url: str) -> dict:
    """The privacy-safe representation of a case used by every channel."""
    findings = []
    for d in case.top_detections[:3]:
        findings.append({"title": d.title, "severity": d.severity, "engine": d.engine,
                         "attack": list(d.attack)})
    return {
        "case_id": case.case_id,
        "entity": case.pseudonym or "unknown",
        "risk_score": case.risk_score,
        "context": list(case.context),
        "engines": list(case.engines),
        "attack": list(case.attack),
        "findings": findings,
        "link": f"{dashboard_url.rstrip('/')}/#/case/{case.case_id}",
    }


def _text(p: dict) -> str:
    lines = [f"New Sentry case {p['case_id']}: {p['entity']}, risk {p['risk_score']:.0f}"]
    if p["context"]:
        lines.append("Context: " + ", ".join(p["context"]))
    for f in p["findings"]:
        tech = f" [{', '.join(f['attack'])}]" if f["attack"] else ""
        lines.append(f"• {f['title']} ({f['severity']}, {f['engine']}){tech}")
    lines.append(p["link"])
    return "\n".join(lines)


@dataclass
class Notifier:
    webhook_url: str | None = None
    slack_webhook: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    email_from: str | None = None
    email_to: list[str] = field(default_factory=list)
    dashboard_url: str = "http://localhost:8000"

    @classmethod
    def from_env(cls) -> Notifier:
        env = os.environ.get
        return cls(
            webhook_url=env("ITDS_ALERT_WEBHOOK_URL"),
            slack_webhook=env("ITDS_ALERT_SLACK_WEBHOOK"),
            smtp_host=env("ITDS_ALERT_SMTP_HOST"),
            smtp_port=int(env("ITDS_ALERT_SMTP_PORT", "587")),
            smtp_user=env("ITDS_ALERT_SMTP_USER"),
            smtp_password=env("ITDS_ALERT_SMTP_PASSWORD"),
            email_from=env("ITDS_ALERT_EMAIL_FROM"),
            email_to=[a.strip() for a in env("ITDS_ALERT_EMAIL_TO", "").split(",") if a.strip()],
            dashboard_url=env("ITDS_DASHBOARD_URL", "http://localhost:8000"),
        )

    @property
    def channels(self) -> list[str]:
        out = []
        if self.webhook_url:
            out.append("webhook")
        if self.slack_webhook:
            out.append("slack")
        if self.smtp_host and self.email_to and self.email_from:
            out.append("email")
        return out

    def _post_json(self, url: str, body: dict) -> None:
        if not url.lower().startswith(("https://", "http://")):
            raise ValueError("alert URLs must be http(s)")
        req = urllib.request.Request(
            url, data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "sentry-itds"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:  # noqa: S310 - scheme checked
            resp.read()

    def _email(self, payloads: list[dict]) -> None:
        msg = EmailMessage()
        n = len(payloads)
        msg["Subject"] = f"Sentry: {n} new case{'s' if n != 1 else ''}"
        msg["From"] = self.email_from
        msg["To"] = ", ".join(self.email_to)
        msg.set_content("\n\n".join(_text(p) for p in payloads))
        with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=TIMEOUT) as smtp:
            smtp.starttls(context=ssl.create_default_context())
            if self.smtp_user:
                smtp.login(self.smtp_user, self.smtp_password or "")
            smtp.send_message(msg)

    def notify(self, cases: list) -> dict[str, str]:
        """Send new cases to every configured channel. Never raises: a broken
        webhook must not stop the detection run. Returns channel -> status."""
        if not cases or not self.channels:
            return {}
        payloads = [case_payload(c, self.dashboard_url) for c in cases]
        status: dict[str, str] = {}
        if self.webhook_url:
            try:
                for p in payloads:
                    self._post_json(self.webhook_url, {"source": "sentry-itds", "case": p})
                status["webhook"] = f"sent {len(payloads)}"
            except Exception as exc:  # noqa: BLE001
                status["webhook"] = f"failed: {exc}"
        if self.slack_webhook:
            try:
                for p in payloads:
                    self._post_json(self.slack_webhook, {"text": _text(p)})
                status["slack"] = f"sent {len(payloads)}"
            except Exception as exc:  # noqa: BLE001
                status["slack"] = f"failed: {exc}"
        if "email" in self.channels:
            try:
                self._email(payloads)
                status["email"] = f"sent {len(payloads)}"
            except Exception as exc:  # noqa: BLE001
                status["email"] = f"failed: {exc}"
        return status
