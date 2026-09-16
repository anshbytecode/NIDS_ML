import os
import sys
import json
import logging
from typing import Dict, Any

if sys.stdout and hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

class AlertDispatcher:
    """
    Multi-channel security alert notification dispatcher.
    Supports terminal broadcast, webhook dispatch, and local security event alerts.
    """
    def __init__(self, webhook_url: str = None):
        self.webhook_url = webhook_url

    def dispatch(self, alert_data: Dict[str, Any]):
        severity = alert_data.get("severity", "MEDIUM")
        attack_type = alert_data.get("attack_type", "Unknown")
        src_ip = alert_data.get("src_ip", "0.0.0.0")
        dst_ip = alert_data.get("dst_ip", "0.0.0.0")
        dst_port = alert_data.get("dst_port", 0)
        threat_score = alert_data.get("threat_score", 0.0)
        confidence = alert_data.get("confidence", 0.0)

        # Terminal banner format
        color_code = "\033[91m" if severity in ["HIGH", "CRITICAL"] else "\033[93m"
        reset_code = "\033[0m"

        msg = (
            f"\n{color_code}🚨 [NIDS ALERT - {severity}]{reset_code}\n"
            f"  • Threat Category: {attack_type}\n"
            f"  • Origin / Target: {src_ip} -> {dst_ip}:{dst_port}\n"
            f"  • Threat Score:    {threat_score} / 100 (Confidence: {confidence*100:.1f}%)\n"
            f"  • Action Required: {alert_data.get('mitigation', 'Inspect packet log')}\n"
        )
        print(msg)
        logging.warning(f"Security Alert: {attack_type} from {src_ip} targeting {dst_ip}:{dst_port} [Score: {threat_score}]")

        # Optional Webhook / Telegram dispatch simulation
        if self.webhook_url:
            self._send_webhook(alert_data)

    def _send_webhook(self, alert_data: Dict[str, Any]):
        # Mock or live HTTP POST to SIEM/Slack/Discord webhook
        try:
            import urllib.request
            payload = json.dumps({
                "text": f"🚨 *NIDS Security Alert: {alert_data.get('attack_type')}*\nAttacker: `{alert_data.get('src_ip')}` | Severity: *{alert_data.get('severity')}*"
            }).encode('utf-8')
            req = urllib.request.Request(self.webhook_url, data=payload, headers={'Content-Type': 'application/json'})
            urllib.request.urlopen(req, timeout=3)
        except Exception as e:
            logging.debug(f"Webhook dispatch skipped or failed: {e}")

notifier = AlertDispatcher()
