#!/usr/bin/env python3
"""
Baseline Management Module
Handles creation, storage, and comparison of registry baselines.
"""

import json
import logging
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, Any

logger = logging.getLogger(__name__)

class BaselineManager:
    """Manage registry baseline snapshots for integrity checking."""
    
    def __init__(self, baseline_dir: str = "baselines"):
        """Initialize baseline manager with storage directory."""
        self.baseline_dir = Path(baseline_dir)
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self.baseline_file = self.baseline_dir / "registry_baseline.json"
        self.baseline_data = {}
    
    def create_baseline(self) -> bool:
        """
        Create a new registry baseline snapshot.
        
        Returns:
            True if baseline created successfully
        """
        try:
            from registry_monitor import RegistryMonitor
            
            monitor = RegistryMonitor()
            snapshot = monitor.capture_registry_state()
            
            baseline = {
                'timestamp': datetime.now().isoformat(),
                'snapshot': snapshot,
                'hash': self._calculate_hash(snapshot)
            }
            
            self.baseline_data = baseline
            self._save_baseline(baseline)
            logger.info(f"Baseline created: {self.baseline_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create baseline: {str(e)}")
            return False
    
    def load_baseline(self) -> bool:
        """
        Load existing registry baseline.
        
        Returns:
            True if baseline loaded successfully
        """
        try:
            if not self.baseline_file.exists():
                logger.warning(f"Baseline file not found: {self.baseline_file}")
                return False
            
            with open(self.baseline_file, 'r') as f:
                self.baseline_data = json.load(f)
            
            logger.info(f"Baseline loaded: {self.baseline_file}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load baseline: {str(e)}")
            return False
    
    def baseline_exists(self) -> bool:
        """
        Check if a baseline file exists.
        
        Returns:
            True if baseline exists
        """
        return self.baseline_file.exists()
    
    def verify_baseline_integrity(self) -> bool:
        """
        Verify baseline integrity using stored hash.
        
        Returns:
            True if baseline integrity is valid
        """
        if not self.baseline_data:
            return False
        
        try:
            stored_hash = self.baseline_data.get('hash')
            snapshot = self.baseline_data.get('snapshot')
            calculated_hash = self._calculate_hash(snapshot)
            
            is_valid = stored_hash == calculated_hash
            
            if is_valid:
                logger.info("Baseline integrity verified")
            else:
                logger.warning("Baseline integrity check failed")
            
            return is_valid
            
        except Exception as e:
            logger.error(f"Failed to verify baseline integrity: {str(e)}")
            return False
    
    def get_baseline_snapshot(self) -> Dict[str, Any]:
        """
        Get the current baseline snapshot.
        
        Returns:
            Dictionary containing the baseline snapshot
        """
        return self.baseline_data.get('snapshot', {})
    
    def get_baseline_timestamp(self) -> str:
        """
        Get the timestamp when baseline was created.
        
        Returns:
            ISO format timestamp string
        """
        return self.baseline_data.get('timestamp', 'Unknown')
    
    def _save_baseline(self, baseline: Dict[str, Any]) -> None:
        """
        Save baseline to JSON file.
        
        Args:
            baseline: Baseline dictionary to save
        """
        try:
            with open(self.baseline_file, 'w') as f:
                json.dump(baseline, f, indent=2, default=str)
            logger.debug(f"Baseline saved to {self.baseline_file}")
        except Exception as e:
            logger.error(f"Failed to save baseline: {str(e)}")
    
    @staticmethod
    def _calculate_hash(data: Dict[str, Any]) -> str:
        """
        Calculate SHA256 hash of baseline data.
        
        Args:
            data: Dictionary to hash
        
        Returns:
            Hexadecimal hash string
        """
        try:
            json_str = json.dumps(data, sort_keys=True, default=str)
            return hashlib.sha256(json_str.encode()).hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate hash: {str(e)}")
            return ""
