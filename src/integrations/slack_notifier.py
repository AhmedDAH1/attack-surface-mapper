"""
Slack Webhook Notifier
Sends security alerts to Slack channels via webhooks.
"""

import requests
import json
from typing import List, Dict
from datetime import datetime


class SlackNotifier:
    """
    Send security alerts to Slack via webhooks.
    
    Features:
    - Critical finding alerts
    - Monitoring change alerts
    - Scan completion notifications
    - Formatted messages with severity colors
    """
    
    SEVERITY_COLORS = {
        'CRITICAL': '#e74c3c',  # Red
        'HIGH': '#e67e22',      # Orange
        'MEDIUM': '#f39c12',    # Yellow
        'LOW': '#27ae60'        # Green
    }
    
    def __init__(self, webhook_url: str):
        """
        Initialize Slack notifier.
        
        Args:
            webhook_url: Slack webhook URL
        """
        self.webhook_url = webhook_url
    
    def send_scan_complete(self, target: str, findings_count: int, 
                          critical_count: int, high_count: int) -> bool:
        """Send scan completion notification"""
        
        if critical_count > 0:
            color = self.SEVERITY_COLORS['CRITICAL']
            status = "🔴 CRITICAL ISSUES DETECTED"
        elif high_count > 0:
            color = self.SEVERITY_COLORS['HIGH']
            status = "🟠 HIGH SEVERITY ISSUES FOUND"
        else:
            color = self.SEVERITY_COLORS['LOW']
            status = "✅ SCAN COMPLETE"
        
        payload = {
            "attachments": [{
                "color": color,
                "title": "Attack Surface Mapper - Scan Complete",
                "text": status,
                "fields": [
                    {"title": "Target", "value": target, "short": True},
                    {"title": "Total Findings", "value": str(findings_count), "short": True},
                    {"title": "Critical Issues", "value": str(critical_count), "short": True},
                    {"title": "High Severity", "value": str(high_count), "short": True}
                ]
            }]
        }
        
        return self._send_webhook(payload)
    
    def send_monitoring_change(self, target: str, changes: List) -> bool:
        """Send monitoring change detection alert"""
        
        change_summary = []
        for change in changes[:5]:
            emoji = "🔴" if change.severity == "CRITICAL" else "🟠" if change.severity == "HIGH" else "🟡"
            change_summary.append(f"{emoji} {change.description}")
        
        changes_text = "\n".join(change_summary)
        
        payload = {
            "attachments": [{
                "color": self.SEVERITY_COLORS['HIGH'],
                "title": "⚠️ Attack Surface Changes Detected",
                "text": f"Monitoring detected {len(changes)} change(s) on {target}",
                "fields": [{"title": "Changes", "value": changes_text, "short": False}]
            }]
        }
        
        return self._send_webhook(payload)
    
    def _send_webhook(self, payload: Dict) -> bool:
        """Send webhook to Slack"""
        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={'Content-Type': 'application/json'},
                timeout=10
            )
            
            if response.status_code == 200:
                print("[✓] Slack notification sent successfully")
                return True
            else:
                print(f"[!] Slack notification failed: {response.status_code}")
                return False
        
        except Exception as e:
            print(f"[!] Slack notification error: {e}")
            return False


def main():
    print("Slack Notifier - Use through main.py with --slack-webhook flag")


if __name__ == '__main__':
    main()
