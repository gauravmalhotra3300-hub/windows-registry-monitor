#!/usr/bin/env python3
"""
Registry Monitoring Module
Handles real-time and periodic monitoring of Windows Registry keys.
"""

import winreg
import logging
from datetime import datetime
from typing import Dict, List, Any

logger = logging.getLogger(__name__)

class RegistryMonitor:
    """Monitor Windows Registry for changes and suspicious modifications."""
    
    # Critical registry paths to monitor
    SENSITIVE_KEYS = {
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': 'User autorun keys',
        'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run': 'System autorun keys',
        'HKLM\\Software\\Microsoft\\Windows Defender': 'Windows Defender settings',
        'HKLM\\Software\\Policies\\Microsoft\\Windows Defender': 'Defender policies',
        'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies': 'User policies',
    }
    
    def __init__(self):
        """Initialize the registry monitor."""
        self.current_snapshot = {}
        self.changes = []
    
    def capture_registry_state(self) -> Dict[str, Any]:
        """
        Capture current state of sensitive registry keys.
        
        Returns:
            Dictionary containing registry key values
        """
        snapshot = {}
        
        for key_path in self.SENSITIVE_KEYS.keys():
            try:
                values = self._read_registry_key(key_path)
                snapshot[key_path] = values
                logger.debug(f"Captured {key_path}: {len(values)} entries")
            except Exception as e:
                logger.warning(f"Failed to read {key_path}: {str(e)}")
        
        return snapshot
    
    def _read_registry_key(self, key_path: str) -> Dict[str, Any]:
        """
        Read all values from a registry key.
        
        Args:
            key_path: Registry key path (e.g., HKCU\\Software\\...)
        
        Returns:
            Dictionary of value names and their data
        """
        values = {}
        
        # Parse hive and subkey
        parts = key_path.split('\\\\')
        hive_name = parts[0]
        subkey = '\\\\'.join(parts[1:])
        
        # Map hive names to registry constants
        hives = {
            'HKCU': winreg.HKEY_CURRENT_USER,
            'HKLM': winreg.HKEY_LOCAL_MACHINE,
            'HKU': winreg.HKEY_USERS,
        }
        
        hive = hives.get(hive_name)
        if not hive:
            raise ValueError(f"Unknown registry hive: {hive_name}")
        
        try:
            with winreg.OpenKey(hive, subkey) as reg_key:
                index = 0
                while True:
                    try:
                        name, value, value_type = winreg.EnumValue(reg_key, index)
                        values[name] = {
                            'value': value,
                            'type': value_type,
                            'timestamp': datetime.now().isoformat()
                        }
                        index += 1
                    except OSError:
                        break
        except OSError as e:
            logger.warning(f"Cannot open registry key {key_path}: {str(e)}")
        
        return values
    
    def detect_changes(self, previous_snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Compare current snapshot with previous snapshot to detect changes.
        
        Args:
            previous_snapshot: Previous registry state
        
        Returns:
            List of detected changes
        """
        changes = []
        current = self.current_snapshot
        
        # Check for new and modified values
        for key_path, current_values in current.items():
            prev_values = previous_snapshot.get(key_path, {})
            
            for value_name, current_data in current_values.items():
                if value_name not in prev_values:
                    # New value detected
                    changes.append({
                        'type': 'NEW',
                        'key_path': key_path,
                        'value_name': value_name,
                        'new_value': current_data['value'],
                        'timestamp': datetime.now().isoformat()
                    })
                    logger.info(f"New registry value detected: {key_path}\\{value_name}")
                elif current_data['value'] != prev_values[value_name]['value']:
                    # Modified value detected
                    changes.append({
                        'type': 'MODIFIED',
                        'key_path': key_path,
                        'value_name': value_name,
                        'old_value': prev_values[value_name]['value'],
                        'new_value': current_data['value'],
                        'timestamp': datetime.now().isoformat()
                    })
                    logger.info(f"Modified registry value: {key_path}\\{value_name}")
        
        # Check for deleted values
        for key_path, prev_values in previous_snapshot.items():
            current_values = current.get(key_path, {})
            
            for value_name, prev_data in prev_values.items():
                if value_name not in current_values:
                    changes.append({
                        'type': 'DELETED',
                        'key_path': key_path,
                        'value_name': value_name,
                        'old_value': prev_data['value'],
                        'timestamp': datetime.now().isoformat()
                    })
                    logger.info(f"Deleted registry value: {key_path}\\{value_name}")
        
        return changes
    
    def monitor_registry(self, previous_snapshot: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """
        Monitor registry and detect changes.
        
        Args:
            previous_snapshot: Previous registry state for comparison
        
        Returns:
            List of detected changes
        """
        logger.info("Starting registry monitoring...")
        self.current_snapshot = self.capture_registry_state()
        
        if previous_snapshot:
            self.changes = self.detect_changes(previous_snapshot)
        
        return self.changes
