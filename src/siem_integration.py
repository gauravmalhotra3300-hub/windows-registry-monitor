"""SIEM platform integration for centralized security monitoring.

This module integrates registry monitoring with major SIEM platforms
including Splunk, ELK, ArcSight, and Elasticsearch.
"""

import json
import logging
from typing import Dict, List, Optional
from datetime import datetime
import urllib.request
import urllib.error


class SIEMConnector:
    """Base class for SIEM platform connectors."""
    
    def __init__(self, siem_type: str):
        """Initialize SIEM connector.
        
        Args:
            siem_type: Type of SIEM platform
        """
        self.siem_type = siem_type
        self.logger = logging.getLogger(__name__)
        self.connected = False
        
    def connect(self) -> bool:
        """Connect to SIEM platform.
        
        Returns:
            True if connection successful
        """
        raise NotImplementedError()
    
    def send_event(self, event_data: Dict) -> bool:
        """Send event to SIEM.
        
        Args:
            event_data: Event to send
            
        Returns:
            True if sent successfully
        """
        raise NotImplementedError()


class SplunkConnector(SIEMConnector):
    """Splunk SIEM connector."""
    
    def __init__(self, splunk_host: str, splunk_port: int, auth_token: str):
        """Initialize Splunk connector.
        
        Args:
            splunk_host: Splunk server hostname
            splunk_port: HEC port (usually 8088)
            auth_token: HEC authentication token
        """
        super().__init__("Splunk")
        self.splunk_host = splunk_host
        self.splunk_port = splunk_port
        self.auth_token = auth_token
        self.hec_endpoint = f"https://{splunk_host}:{splunk_port}/services/collector"
        
    def send_event(self, event_data: Dict) -> bool:
        """Send event to Splunk HEC.
        
        Args:
            event_data: Event data
            
        Returns:
            True if sent successfully
        """
        try:
            # Format event for Splunk
            hec_event = {
                "event": event_data,
                "sourcetype": "windows:registry:monitor",
                "source": event_data.get('source_system', 'unknown')
            }
            
            payload = json.dumps(hec_event).encode('utf-8')
            
            request = urllib.request.Request(
                self.hec_endpoint,
                data=payload,
                headers={
                    'Authorization': f'Splunk {self.auth_token}',
                    'Content-Type': 'application/json'
                }
            )
            
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status == 200:
                    self.logger.info("Event sent to Splunk")
                    return True
                    
        except Exception as e:
            self.logger.error(f"Error sending to Splunk: {e}")
        
        return False


class ElasticsearchConnector(SIEMConnector):
    """Elasticsearch/ELK SIEM connector."""
    
    def __init__(self, es_host: str, es_port: int = 9200, index_name: str = "registry-monitor"):
        """Initialize Elasticsearch connector.
        
        Args:
            es_host: Elasticsearch server
            es_port: Elasticsearch port
            index_name: Index name for events
        """
        super().__init__("Elasticsearch")
        self.es_host = es_host
        self.es_port = es_port
        self.index_name = index_name
        self.es_endpoint = f"http://{es_host}:{es_port}"
        
    def send_event(self, event_data: Dict) -> bool:
        """Send event to Elasticsearch.
        
        Args:
            event_data: Event data
            
        Returns:
            True if sent successfully
        """
        try:
            # Add timestamp if not present
            if '@timestamp' not in event_data:
                event_data['@timestamp'] = datetime.utcnow().isoformat()
            
            # Generate document ID based on timestamp and hash
            doc_id = f"{event_data.get('source_system', 'unknown')}-{datetime.now().timestamp()}"
            
            url = f"{self.es_endpoint}/{self.index_name}/_doc/{doc_id}"
            payload = json.dumps(event_data).encode('utf-8')
            
            request = urllib.request.Request(
                url,
                data=payload,
                headers={'Content-Type': 'application/json'},
                method='POST'
            )
            
            with urllib.request.urlopen(request, timeout=10) as response:
                if response.status in [200, 201]:
                    self.logger.info("Event sent to Elasticsearch")
                    return True
                    
        except Exception as e:
            self.logger.error(f"Error sending to Elasticsearch: {e}")
        
        return False


class SIEMEventFormatter:
    """Format registry events for SIEM consumption."""
    
    @staticmethod
    def format_for_siem(event_data: Dict) -> Dict:
        """Format event data for SIEM ingestion.
        
        Args:
            event_data: Raw event data
            
        Returns:
            Formatted event data
        """
        return {
            'timestamp': event_data.get('timestamp', datetime.now().isoformat()),
            'source_system': event_data.get('source_system', 'unknown'),
            'event_type': 'registry_modification',
            'severity': SIEMEventFormatter._map_severity(event_data.get('risk_level')),
            'message': event_data.get('description', ''),
            'registry_key': event_data.get('key_path'),
            'registry_value': event_data.get('value_name'),
            'old_value': event_data.get('old_value'),
            'new_value': event_data.get('new_value'),
            'change_type': event_data.get('change_type'),
            'detection_method': event_data.get('detection_method', 'BASELINE_COMPARISON'),
            'fields': {
                'risk_level': event_data.get('risk_level'),
                'alert_type': event_data.get('alert_type'),
                'hostname': event_data.get('hostname')
            }
        }
    
    @staticmethod
    def _map_severity(risk_level: str) -> str:
        """Map registry risk level to SIEM severity.
        
        Args:
            risk_level: Registry change risk level
            
        Returns:
            SIEM severity level
        """
        severity_map = {
            'CRITICAL': 'critical',
            'HIGH': 'high',
            'MEDIUM': 'medium',
            'LOW': 'low'
        }
        return severity_map.get(risk_level, 'medium')


class SIEMIntegrationManager:
    """Manage multiple SIEM connectors."""
    
    def __init__(self):
        """Initialize SIEM manager."""
        self.logger = logging.getLogger(__name__)
        self.connectors = {}
        
    def add_connector(self, connector_id: str, connector: SIEMConnector):
        """Add SIEM connector.
        
        Args:
            connector_id: Unique connector ID
            connector: SIEM connector instance
        """
        self.connectors[connector_id] = connector
        self.logger.info(f"SIEM connector added: {connector_id}")
        
    def send_event_to_all(self, event_data: Dict) -> bool:
        """Send event to all configured SIEM platforms.
        
        Args:
            event_data: Event to send
            
        Returns:
            True if at least one succeeded
        """
        formatted_event = SIEMEventFormatter.format_for_siem(event_data)
        success = False
        
        for connector_id, connector in self.connectors.items():
            try:
                if connector.send_event(formatted_event):
                    success = True
            except Exception as e:
                self.logger.error(f"Error with connector {connector_id}: {e}")
        
        return success
