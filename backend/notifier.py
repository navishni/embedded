"""Push notifications to the administrator through ntfy."""
import logging
from datetime import datetime

import requests

log = logging.getLogger(__name__)


class Notifier:
    def __init__(self, server, topic, token="", dashboard_url=""):
        self.url = f"{server.rstrip('/')}/{topic}" if topic else ""
        self.token = token
        self.dashboard_url = dashboard_url.rstrip("/")

    @property
    def enabled(self):
        return bool(self.url)

    def send_intrusion(self, incident):
        """Send an alert. The evidence image is deliberately NOT attached:
        ntfy topics can be public, so only metadata and a dashboard link leave
        the server. Returns True on success."""
        if not self.enabled:
            return False
        when = datetime.fromtimestamp(incident["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
        body = (f"{incident['person_count']} person(s) in restricted zone\n"
                f"Camera: {incident['camera_id']}\nTime: {when}\n"
                f"Incident: {incident['id']}")
        headers = {
            "Title": "INTRUSION ALERT",
            "Priority": "urgent",
            "Tags": "rotating_light,warning",
        }
        if self.dashboard_url:
            headers["Click"] = f"{self.dashboard_url}/incident/{incident['id']}"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        try:
            r = requests.post(self.url, data=body.encode(), headers=headers, timeout=5)
            r.raise_for_status()
            return True
        except requests.RequestException as e:
            log.warning("ntfy notification failed: %s", e)
            return False
