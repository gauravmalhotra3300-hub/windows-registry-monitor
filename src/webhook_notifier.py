"""Webhook integration for registry alert notifications.

This module provides webhook capabilities to send registry change alerts
to external systems such as Slack, Teams, Discord, or custom webhooks.
"""

import json
import logging
import threading
from typing import Dict, List, Optional, Callable
from datetime import datetime
import urllib.request
import urllib.error
from urllib.parse import urljoin


class WebhookNotifier:
    """Send registry alerts to webhooks."""
    
    def __init__(self, webhook_urls: List[str] = None):
        """Initialize webhook notifier.
        
        Args:
            webhook_urls: List of webhook URLs to send alerts to
        """
        self.webhook_urls = webhook_urls or []
        self.logger = logging.getLogger(__name__)
        self.retry_attempts = 3
        self.timeout = 10
        
    def add_webhook(self, url: str) -> bool:
        """Add a webhook URL.
        
        Args:
            url: Webhook URL
            
        Returns:
            True if webhook is valid, False otherwise
        """
        if url not in self.webhook_urls:
            try:
                # Basic validation of webhook URL
                if url.startswith('http://') or url.startswith('https://'):
                    self.webhook_urls.append(url)
                    self.logger.info(f"Webhook added: {url}")
                    return True
            except Exception as e:
                self.logger.error(f"Invalid webhook URL: {e}")
        return False
    
    def remove_webhook(self, url: str):
        """Remove a webhook URL.
        
        Args:
            url: Webhook URL to remove
        """
        if url in self.webhook_urls:
            self.webhook_urls.remove(url)
            self.logger.info(f"Webhook removed: {url}")
    
    def send_alert(self, alert_data: Dict) -> bool:
        """Send alert to all configured webhooks.
        
        Args:
            alert_data: Alert data to send
            
        Returns:
            True if at least one webhook succeeded
        """
        if not self.webhook_urls:
            self.logger.warning("No webhooks configured")
            return False
        
        success = False
        for webhook_url in self.webhook_urls:
            if self._send_to_webhook(webhook_url, alert_data):
                success = True
        
        return success
    
    def _send_to_webhook(self, webhook_url: str, alert_data: Dict) -> bool:
        """Send alert to a specific webhook.
        
        Args:
            webhook_url: Webhook URL
            alert_data: Alert data
            
        Returns:
            True if successful
        """
        try:
            payload = json.dumps(alert_data).encode('utf-8')
            
            request = urllib.request.Request(
                webhook_url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            for attempt in range(self.retry_attempts):
                try:
                    with urllib.request.urlopen(request, timeout=self.timeout) as response:
                        status = response.status
                        if 200 <= status < 300:
                            self.logger.info(f"Webhook sent successfully: {webhook_url}")
                            return True
                except urllib.error.URLError as e:
                    if attempt < self.retry_attempts - 1:
                        self.logger.warning(f"Webhook attempt {attempt + 1} failed, retrying...")
                        continue
                    else:
                        self.logger.error(f"Webhook failed after {self.retry_attempts} attempts: {e}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Error sending webhook to {webhook_url}: {e}")
            return False
    
    def send_alert_async(self, alert_data: Dict):
        """Send alert asynchronously.
        
        Args:
            alert_data: Alert data to send
        """
        thread = threading.Thread(target=self.send_alert, args=(alert_data,))
        thread.daemon = True
        thread.start()


class SlackWebhookNotifier(WebhookNotifier):
    """Send alerts to Slack via webhook."""
    
    def __init__(self, webhook_url: str = None):
        """Initialize Slack webhook notifier.
        
        Args:
            webhook_url: Slack webhook URL
        """
        super().__init__()
        if webhook_url:
            self.add_webhook(webhook_url)
    
    def send_alert(self, alert_data: Dict) -> bool:
        """Format and send alert to Slack.
        
        Args:
            alert_data: Alert data
            
        Returns:
            True if successful
        """
        slack_message = self._format_slack_message(alert_data)
        return super().send_alert(slack_message)
    
    def _format_slack_message(self, alert_data: Dict) -> Dict:
        """Format alert data for Slack.
        
        Args:
            alert_data: Alert data
            
        Returns:
            Formatted message for Slack
        """
        color = "danger" if alert_data.get('risk_level') == 'CRITICAL' else "warning"
        
        return {
            "attachments": [
                {
                    "color": color,
                    "title": alert_data.get('type', 'Registry Alert'),
                    "text": alert_data.get('description', 'Registry modification detected'),
                    "fields": [
                        {"title": "Risk Level", "value": alert_data.get('risk_level', 'N/A'), "short": True},
                        {"title": "Key Path", "value": alert_data.get('key_path', 'N/A'), "short": False},
                        {"title": "Timestamp", "value": alert_data.get('timestamp', 'N/A'), "short": True}
                    ]
                }
            ]
        }


class TeamsWebhookNotifier(WebhookNotifier):
    """Send alerts to Microsoft Teams via webhook."""
    
    def __init__(self, webhook_url: str = None):
        """Initialize Teams webhook notifier.
        
        Args:
            webhook_url: Microsoft Teams webhook URL
        """
        super().__init__()
        if webhook_url:
            self.add_webhook(webhook_url)
    
    def send_alert(self, alert_data: Dict) -> bool:
        """Format and send alert to Teams.
        
        Args:
            alert_data: Alert data
            
        Returns:
            True if successful
        """
        teams_message = self._format_teams_message(alert_data)
        return super().send_alert(teams_message)
    
    def _format_teams_message(self, alert_data: Dict) -> Dict:
        """Format alert data for Microsoft Teams.
        
        Args:
            alert_data: Alert data
            
        Returns:
            Formatted message for Teams
        """
        theme_color = "FF0000" if alert_data.get('risk_level') == 'CRITICAL' else "FFA500"
        
        return {
            "@type": "MessageCard",
            "@context": "https://schema.org/extensions",
            "summary": alert_data.get('type', 'Registry Alert'),
            "themeColor": theme_color,
            "title": alert_data.get('type', 'Registry Alert'),
            "sections": [
                {
                    "activityTitle": alert_data.get('description', 'Registry modification detected'),
                    "facts": [
                        {"name": "Risk Level", "value": alert_data.get('risk_level', 'N/A')},
                        {"name": "Registry Key", "value": alert_data.get('key_path', 'N/A')},
                        {"name": "Timestamp", "value": alert_data.get('timestamp', 'N/A')}
                    ]
                }
            ]
        }
