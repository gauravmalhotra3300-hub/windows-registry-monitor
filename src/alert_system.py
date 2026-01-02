#!/usr/bin/env python3
"""
Alert System Module
Analyzes registry changes and generates alerts for suspicious activity.
"""

import logging
from datetime import datetime
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class AlertSystem:
    """Analyze registry changes and generate security alerts."""
    
    # Malware behavior patterns
    MALWARE_PATTERNS = {
        'defender_disable': ['Windows Defender', 'WinDefend', 'MpEngine'],
        'persistence': ['Run', 'RunOnce', 'Startup'],
        'shell_replacement': ['Shell', 'UserInit'],
        'uac_bypass': ['Elevate', 'UAC'],
        'network_redirect': ['ProxyEnable', 'ProxyServer'],
    }
    
    # Risk levels
    RISK_LEVELS = {
        'CRITICAL': 'CRITICAL',
        'HIGH': 'HIGH',
        'MEDIUM': 'MEDIUM',
        'LOW': 'LOW',
        'INFO': 'INFO'
    }
    
    def __init__(self):
        """Initialize the alert system."""
        self.alerts = []
        self.alert_count = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
    
    def analyze_changes(self, changes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Analyze registry changes for suspicious patterns.
        
        Args:
            changes: List of registry changes
        
        Returns:
            List of generated alerts
        """
        self.alerts = []
        
        for change in changes:
            alert = self._analyze_change(change)
            if alert:
                self.alerts.append(alert)
                risk_level = alert['risk_level']
                self.alert_count[risk_level] += 1
                logger.warning(f"Alert generated: {alert['title']} [{risk_level}]")
        
        return self.alerts
    
    def _analyze_change(self, change: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a single registry change for malware indicators.
        
        Args:
            change: Registry change dictionary
        
        Returns:
            Alert dictionary or None
        """
        key_path = change.get('key_path', '')
        value_name = change.get('value_name', '')
        new_value = change.get('new_value', '')
        change_type = change.get('type', '')
        
        # Check for defender disabling
        if any(pattern in key_path for pattern in self.MALWARE_PATTERNS['defender_disable']):
            return {
                'type': 'SECURITY_THREAT',
                'title': 'Windows Defender Tampering Detected',
                'description': f'Registry modification in security settings detected',
                'risk_level': self.RISK_LEVELS['CRITICAL'],
                'key_path': key_path,
                'value_name': value_name,
                'new_value': str(new_value),
                'timestamp': datetime.now().isoformat()
            }
        
        # Check for persistence mechanisms
        if any(pattern in key_path for pattern in self.MALWARE_PATTERNS['persistence']):
            if change_type == 'NEW':
                return {
                    'type': 'PERSISTENCE_MECHANISM',
                    'title': 'Suspicious Autorun Entry Detected',
                    'description': f'New autorun entry added: {new_value}',
                    'risk_level': self.RISK_LEVELS['HIGH'],
                    'key_path': key_path,
                    'value_name': value_name,
                    'new_value': str(new_value),
                    'timestamp': datetime.now().isoformat()
                }
        
        # Check for shell replacement
        if any(pattern in key_path for pattern in self.MALWARE_PATTERNS['shell_replacement']):
            return {
                'type': 'SYSTEM_MODIFICATION',
                'title': 'Shell or System Startup Modification',
                'description': f'Critical system startup registry modified',
                'risk_level': self.RISK_LEVELS['CRITICAL'],
                'key_path': key_path,
                'value_name': value_name,
                'new_value': str(new_value),
                'timestamp': datetime.now().isoformat()
            }
        
        # Check for UAC bypass attempts
        if any(pattern in key_path for pattern in self.MALWARE_PATTERNS['uac_bypass']):
            return {
                'type': 'PRIVILEGE_ESCALATION',
                'title': 'UAC Bypass Attempt Detected',
                'description': f'Registry modified for privilege escalation',
                'risk_level': self.RISK_LEVELS['CRITICAL'],
                'key_path': key_path,
                'value_name': value_name,
                'new_value': str(new_value),
                'timestamp': datetime.now().isoformat()
            }
        
        # Generic suspicious modification
        if change_type in ['NEW', 'MODIFIED'] and len(str(new_value)) > 500:
            return {
                'type': 'SUSPICIOUS_VALUE',
                'title': 'Unusually Large Registry Value Detected',
                'description': f'Registry value exceeds normal size',
                'risk_level': self.RISK_LEVELS['MEDIUM'],
                'key_path': key_path,
                'value_name': value_name,
                'new_value': f"{str(new_value)[:100]}...",
                'timestamp': datetime.now().isoformat()
            }
        
        return None
    
    def send_alerts(self, alerts: List[Dict[str, Any]]) -> bool:
        """
        Send alerts through configured channels.
        
        Args:
            alerts: List of alerts to send
        
        Returns:
            True if alerts sent successfully
        """
        try:
            for alert in alerts:
                self._log_alert(alert)
            logger.info(f"Sent {len(alerts)} alerts")
            return True
        except Exception as e:
            logger.error(f"Failed to send alerts: {str(e)}")
            return False
    
    def _log_alert(self, alert: Dict[str, Any]) -> None:
        """
        Log an alert to file and console.
        
        Args:
            alert: Alert dictionary
        """
        risk = alert.get('risk_level', 'UNKNOWN')
        title = alert.get('title', 'Unknown Alert')
        
        if risk == 'CRITICAL':
            logger.critical(f"{title}: {alert.get('description', '')}")
        elif risk == 'HIGH':
            logger.error(f"{title}: {alert.get('description', '')}")
        elif risk == 'MEDIUM':
            logger.warning(f"{title}: {alert.get('description', '')}")
        else:
            logger.info(f"{title}: {alert.get('description', '')}")
    
    def get_alert_summary(self) -> Dict[str, Any]:
        """
        Get summary of generated alerts.
        
        Returns:
            Dictionary with alert statistics
        """
        return {
            'total_alerts': len(self.alerts),
            'critical': self.alert_count['CRITICAL'],
            'high': self.alert_count['HIGH'],
            'medium': self.alert_count['MEDIUM'],
            'low': self.alert_count['LOW'],
            'timestamp': datetime.now().isoformat()
        }
