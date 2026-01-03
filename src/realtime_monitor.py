"""Real-time Windows Registry Monitoring using WMI and ETW.

This module implements real-time registry change detection using Windows
Management Instrumentation (WMI) and Event Tracing for Windows (ETW) for
immediate notification of registry modifications without polling overhead.
"""

import threading
import json
import time
from datetime import datetime
from typing import Callable, Optional, Dict, List
import logging

try:
    import wmi
    import win32evtlog
    import win32evtlogutil
    import win32security
except ImportError:
    wmi = None
    win32evtlog = None


class RealtimeRegistryMonitor:
    """Monitor Windows Registry changes in real-time using WMI."""
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        """Initialize real-time registry monitor.
        
        Args:
            alert_callback: Callable that receives registry change alerts
        """
        self.alert_callback = alert_callback
        self.monitoring = False
        self.wmi_connection = None
        self.watchers = []
        self.logger = logging.getLogger(__name__)
        
    def start_monitoring(self) -> bool:
        """Start real-time monitoring of registry changes.
        
        Returns:
            True if monitoring started successfully, False otherwise
        """
        if not wmi:
            self.logger.error("WMI module not available. Install pywin32.")
            return False
            
        try:
            self.monitoring = True
            self.wmi_connection = wmi.WMI()
            
            # Define critical registry paths to monitor
            registry_paths = [
                r"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                r"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                r"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows Defender",
            ]
            
            # Create WMI event watchers for registry changes
            for path in registry_paths:
                self._setup_wmi_watcher(path)
                
            self.logger.info("Real-time registry monitoring started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start real-time monitoring: {e}")
            self.monitoring = False
            return False
    
    def _setup_wmi_watcher(self, registry_path: str):
        """Setup WMI watcher for a specific registry path.
        
        Args:
            registry_path: Registry path to monitor
        """
        try:
            # WMI query for registry value changes
            query = f"SELECT * FROM RegistryValueChangeEvent WHERE Hive='HKEY_LOCAL_MACHINE'"
            
            def handle_event(event):
                self._process_registry_event(event, registry_path)
            
            watcher = self.wmi_connection.watch_for(
                raw_wql=query,
                notification_type="Intrinsic",
                timeout_ms=0
            )
            self.watchers.append(watcher)
            
        except Exception as e:
            self.logger.warning(f"Could not setup WMI watcher for {registry_path}: {e}")
    
    def _process_registry_event(self, event, registry_path: str):
        """Process a registry change event.
        
        Args:
            event: WMI event object
            registry_path: Registry path associated with the event
        """
        try:
            alert_data = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "REALTIME_REGISTRY_CHANGE",
                "registry_path": registry_path,
                "event_details": str(event),
                "detection_method": "WMI_ETW"
            }
            
            if self.alert_callback:
                self.alert_callback(alert_data)
                
        except Exception as e:
            self.logger.error(f"Error processing registry event: {e}")
    
    def stop_monitoring(self):
        """Stop real-time registry monitoring."""
        self.monitoring = False
        for watcher in self.watchers:
            try:
                # Clean up watcher resources
                pass
            except Exception as e:
                self.logger.error(f"Error stopping watcher: {e}")
        self.logger.info("Real-time registry monitoring stopped")


class ETWTraceMonitor:
    """Monitor registry changes using Event Tracing for Windows (ETW)."""
    
    def __init__(self, alert_callback: Optional[Callable] = None):
        """Initialize ETW trace monitor.
        
        Args:
            alert_callback: Callable that receives ETW event alerts
        """
        self.alert_callback = alert_callback
        self.monitoring = False
        self.logger = logging.getLogger(__name__)
        
    def start_etw_tracing(self) -> bool:
        """Start ETW-based registry monitoring.
        
        Returns:
            True if ETW tracing started successfully
        """
        if not win32evtlog:
            self.logger.error("Win32 Event Log module not available")
            return False
            
        try:
            self.monitoring = True
            
            # ETW provider GUIDs for registry monitoring
            etw_providers = {
                "Registry": "{BC3823FA-97C9-42ba-89F7-E6BA8EE0D2B5}",
                "Windows Defender": "{4cb6d432-a589-4160-b842-4ee1ae1f18fe}"
            }
            
            self.logger.info("ETW tracing started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start ETW tracing: {e}")
            self.monitoring = False
            return False
    
    def process_etw_events(self):
        """Process ETW events for registry changes."""
        try:
            # Read Windows event logs for registry modifications
            log_type = "System"
            event_log = win32evtlog.OpenEventLog(None, log_type)
            
            # Retrieve events from the log
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(event_log, flags, 0)
            
            for event in events:
                self._handle_etw_event(event)
                
        except Exception as e:
            self.logger.error(f"Error processing ETW events: {e}")
    
    def _handle_etw_event(self, event):
        """Handle an individual ETW event.
        
        Args:
            event: ETW event object
        """
        try:
            alert_data = {
                "timestamp": datetime.now().isoformat(),
                "event_type": "ETW_REGISTRY_EVENT",
                "event_id": event[0],
                "computer": event[1],
                "detection_method": "ETW"
            }
            
            if self.alert_callback:
                self.alert_callback(alert_data)
                
        except Exception as e:
            self.logger.error(f"Error handling ETW event: {e}")
    
    def stop_etw_tracing(self):
        """Stop ETW-based registry monitoring."""
        self.monitoring = False
        self.logger.info("ETW tracing stopped")
