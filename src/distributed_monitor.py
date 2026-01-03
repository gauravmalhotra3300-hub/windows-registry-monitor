"""Distributed registry monitoring across multiple systems.

This module enables centralized monitoring of Windows Registry changes
across multiple networked systems.
"""

import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
import socket
import threading
from collections import defaultdict


class DistributedMonitor:
    """Manage distributed registry monitoring across multiple systems."""
    
    def __init__(self, central_node_ip: str = None):
        """Initialize distributed monitor.
        
        Args:
            central_node_ip: IP of central monitoring node
        """
        self.central_node_ip = central_node_ip
        self.logger = logging.getLogger(__name__)
        self.monitored_systems = {}
        self.aggregated_alerts = []
        self.system_health = defaultdict(dict)
        
    def register_system(self, system_id: str, hostname: str, ip_address: str) -> bool:
        """Register a system for distributed monitoring.
        
        Args:
            system_id: Unique system identifier
            hostname: System hostname
            ip_address: System IP address
            
        Returns:
            True if registration successful
        """
        try:
            self.monitored_systems[system_id] = {
                'hostname': hostname,
                'ip_address': ip_address,
                'registered_at': datetime.now().isoformat(),
                'status': 'ACTIVE',
                'last_heartbeat': datetime.now().isoformat()
            }
            self.logger.info(f"System registered: {system_id} ({hostname})")
            return True
        except Exception as e:
            self.logger.error(f"Error registering system: {e}")
            return False
    
    def deregister_system(self, system_id: str):
        """Deregister a system from monitoring.
        
        Args:
            system_id: System to deregister
        """
        if system_id in self.monitored_systems:
            del self.monitored_systems[system_id]
            self.logger.info(f"System deregistered: {system_id}")
    
    def submit_alert(self, system_id: str, alert_data: Dict) -> bool:
        """Submit alert from monitored system.
        
        Args:
            system_id: Source system ID
            alert_data: Alert details
            
        Returns:
            True if alert processed successfully
        """
        try:
            if system_id not in self.monitored_systems:
                self.logger.warning(f"Alert from unregistered system: {system_id}")
                return False
            
            # Add source information
            enriched_alert = {
                **alert_data,
                'source_system': system_id,
                'hostname': self.monitored_systems[system_id]['hostname'],
                'received_at': datetime.now().isoformat()
            }
            
            self.aggregated_alerts.append(enriched_alert)
            
            # Update system heartbeat
            self.monitored_systems[system_id]['last_heartbeat'] = datetime.now().isoformat()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error processing alert: {e}")
            return False
    
    def get_system_status(self, system_id: str = None) -> Dict:
        """Get status of monitored systems.
        
        Args:
            system_id: Optional specific system ID
            
        Returns:
            System status information
        """
        if system_id:
            return self.monitored_systems.get(system_id, {})
        return self.monitored_systems
    
    def aggregate_alerts(self, time_window_seconds: int = 300) -> Dict:
        """Aggregate alerts from all systems.
        
        Args:
            time_window_seconds: Time window for aggregation
            
        Returns:
            Aggregated alert statistics
        """
        stats = {
            'total_alerts': len(self.aggregated_alerts),
            'alerts_by_system': defaultdict(int),
            'alerts_by_risk_level': defaultdict(int),
            'critical_alerts': []
        }
        
        for alert in self.aggregated_alerts:
            system = alert.get('source_system', 'UNKNOWN')
            risk_level = alert.get('risk_level', 'UNKNOWN')
            
            stats['alerts_by_system'][system] += 1
            stats['alerts_by_risk_level'][risk_level] += 1
            
            if risk_level == 'CRITICAL':
                stats['critical_alerts'].append(alert)
        
        stats['alerts_by_system'] = dict(stats['alerts_by_system'])
        stats['alerts_by_risk_level'] = dict(stats['alerts_by_risk_level'])
        
        return stats
    
    def export_distributed_report(self, output_file: str):
        """Export aggregated report from all systems.
        
        Args:
            output_file: Output file path
        """
        try:
            report = {
                'generated_at': datetime.now().isoformat(),
                'monitored_systems': self.monitored_systems,
                'total_alerts': len(self.aggregated_alerts),
                'alert_summary': self.aggregate_alerts(),
                'critical_alerts': [
                    a for a in self.aggregated_alerts 
                    if a.get('risk_level') == 'CRITICAL'
                ]
            }
            
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            
            self.logger.info(f"Report exported: {output_file}")
            
        except Exception as e:
            self.logger.error(f"Error exporting report: {e}")


class AgentNode:
    """Agent for local system monitoring in distributed setup."""
    
    def __init__(self, system_id: str, central_server_ip: str, central_server_port: int = 5000):
        """Initialize agent node.
        
        Args:
            system_id: Unique identifier for this system
            central_server_ip: IP of central monitoring server
            central_server_port: Port of central monitoring server
        """
        self.system_id = system_id
        self.central_server_ip = central_server_ip
        self.central_server_port = central_server_port
        self.logger = logging.getLogger(__name__)
        self.connected = False
        
    def send_alert_to_central(self, alert_data: Dict) -> bool:
        """Send alert to central monitoring server.
        
        Args:
            alert_data: Alert to send
            
        Returns:
            True if sent successfully
        """
        try:
            # Package alert with system info
            message = {
                'system_id': self.system_id,
                'alert': alert_data,
                'timestamp': datetime.now().isoformat()
            }
            
            # In production, would use socket/HTTP to send
            self.logger.info(f"Alert prepared for central server: {message}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error sending alert: {e}")
            return False
