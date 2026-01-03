"""Machine learning-based anomaly detection for registry changes.

This module uses statistical methods and machine learning techniques
to detect anomalous registry patterns that deviate from normal behavior.
"""

import json
import logging
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
from collections import defaultdict
import statistics


class AnomalyDetector:
    """Detect anomalous registry change patterns."""
    
    def __init__(self, sensitivity: float = 0.7):
        """Initialize anomaly detector.
        
        Args:
            sensitivity: Detection sensitivity (0.0-1.0)
        """
        self.sensitivity = sensitivity
        self.logger = logging.getLogger(__name__)
        self.baseline_stats = {}
        self.change_history = []
        self.anomalies = []
        
    def train_baseline(self, historical_changes: List[Dict]):
        """Train anomaly detector with historical baseline data.
        
        Args:
            historical_changes: List of historical registry changes
        """
        try:
            self.change_history = historical_changes
            
            # Extract statistics from historical data
            change_frequencies = defaultdict(int)
            change_types = defaultdict(int)
            time_intervals = []
            value_sizes = []
            
            for i, change in enumerate(historical_changes):
                key_path = change.get('key_path', '')
                change_type = change.get('change_type', '')
                
                change_frequencies[key_path] += 1
                change_types[change_type] += 1
                
                # Analyze value sizes
                new_value = change.get('new_value', '')
                if new_value:
                    value_sizes.append(len(str(new_value)))
                
                # Analyze time intervals
                if i > 0:
                    try:
                        current_time = datetime.fromisoformat(change.get('timestamp', ''))
                        prev_time = datetime.fromisoformat(historical_changes[i-1].get('timestamp', ''))
                        interval = (current_time - prev_time).total_seconds()
                        if interval > 0:
                            time_intervals.append(interval)
                    except:
                        pass
            
            # Store baseline statistics
            self.baseline_stats = {
                'change_frequencies': dict(change_frequencies),
                'change_types': dict(change_types),
                'avg_value_size': statistics.mean(value_sizes) if value_sizes else 0,
                'median_time_interval': statistics.median(time_intervals) if time_intervals else 0,
                'max_changes_per_key': max(change_frequencies.values()) if change_frequencies else 1
            }
            
            self.logger.info("Baseline training completed")
            
        except Exception as e:
            self.logger.error(f"Error during baseline training: {e}")
    
    def detect_anomalies(self, recent_changes: List[Dict]) -> List[Dict]:
        """Detect anomalies in recent registry changes.
        
        Args:
            recent_changes: List of recent registry changes
            
        Returns:
            List of detected anomalies
        """
        detected_anomalies = []
        
        for change in recent_changes:
            anomaly_score = self._calculate_anomaly_score(change)
            
            if anomaly_score >= (1.0 - self.sensitivity):
                anomaly_record = {
                    **change,
                    'anomaly_score': anomaly_score,
                    'anomaly_type': self._classify_anomaly(change),
                    'detected_at': datetime.now().isoformat()
                }
                detected_anomalies.append(anomaly_record)
                self.anomalies.append(anomaly_record)
        
        return detected_anomalies
    
    def _calculate_anomaly_score(self, change: Dict) -> float:
        """Calculate anomaly score for a registry change.
        
        Args:
            change: Registry change data
            
        Returns:
            Anomaly score (0.0-1.0)
        """
        scores = []
        
        # Score 1: Key frequency analysis
        key_path = change.get('key_path', '')
        baseline_freq = self.baseline_stats.get('change_frequencies', {}).get(key_path, 0)
        if baseline_freq == 0:
            scores.append(0.8)  # Unknown key is suspicious
        else:
            scores.append(0.1)  # Known key is normal
        
        # Score 2: Change type analysis
        change_type = change.get('change_type', '')
        baseline_types = self.baseline_stats.get('change_types', {})
        total_baseline_changes = sum(baseline_types.values())
        type_frequency = baseline_types.get(change_type, 0) / total_baseline_changes if total_baseline_changes > 0 else 0.5
        
        if type_frequency < 0.1:
            scores.append(0.7)  # Rare change type
        else:
            scores.append(0.2)  # Common change type
        
        # Score 3: Value size analysis
        new_value = change.get('new_value', '')
        value_size = len(str(new_value))
        baseline_avg_size = self.baseline_stats.get('avg_value_size', 100)
        
        if baseline_avg_size > 0:
            size_ratio = value_size / baseline_avg_size
            if size_ratio > 5.0:
                scores.append(0.9)  # Unusually large value
            elif size_ratio < 0.1:
                scores.append(0.3)  # Unusually small value
            else:
                scores.append(0.1)  # Normal size
        
        # Score 4: Risk level analysis
        risk_level = change.get('risk_level', 'LOW')
        risk_scores = {'CRITICAL': 1.0, 'HIGH': 0.8, 'MEDIUM': 0.5, 'LOW': 0.2}
        scores.append(risk_scores.get(risk_level, 0.5))
        
        # Calculate weighted average
        if scores:
            return sum(scores) / len(scores)
        return 0.0
    
    def _classify_anomaly(self, change: Dict) -> str:
        """Classify the type of anomaly detected.
        
        Args:
            change: Registry change data
            
        Returns:
            Anomaly classification
        """
        risk_level = change.get('risk_level', 'LOW')
        
        if risk_level == 'CRITICAL':
            return 'CRITICAL_CHANGE'
        elif change.get('key_path', '').lower().find('defender') >= 0:
            return 'SECURITY_SOFTWARE_TAMPERING'
        elif change.get('change_type') == 'ADDED':
            return 'NEW_PERSISTENCE_MECHANISM'
        elif change.get('alert_type') == 'PERSISTENCE_MECHANISM':
            return 'AUTORUN_MODIFICATION'
        else:
            return 'GENERAL_ANOMALY'
    
    def get_anomaly_statistics(self) -> Dict:
        """Get statistics on detected anomalies.
        
        Returns:
            Dictionary with anomaly statistics
        """
        if not self.anomalies:
            return {
                'total_anomalies': 0,
                'critical': 0,
                'high': 0,
                'medium': 0
            }
        
        stats = {
            'total_anomalies': len(self.anomalies),
            'critical': sum(1 for a in self.anomalies if a.get('risk_level') == 'CRITICAL'),
            'high': sum(1 for a in self.anomalies if a.get('risk_level') == 'HIGH'),
            'medium': sum(1 for a in self.anomalies if a.get('risk_level') == 'MEDIUM'),
            'anomaly_types': defaultdict(int)
        }
        
        for anomaly in self.anomalies:
            anom_type = anomaly.get('anomaly_type', 'UNKNOWN')
            stats['anomaly_types'][anom_type] += 1
        
        stats['anomaly_types'] = dict(stats['anomaly_types'])
        return stats
    
    def export_anomalies(self, output_file: str):
        """Export detected anomalies to JSON file.
        
        Args:
            output_file: Output file path
        """
        try:
            with open(output_file, 'w') as f:
                json.dump(self.anomalies, f, indent=2)
            self.logger.info(f"Anomalies exported to {output_file}")
        except Exception as e:
            self.logger.error(f"Error exporting anomalies: {e}")


class BehavioralAnalyzer:
    """Analyze registry change behavior patterns."""
    
    def __init__(self):
        """Initialize behavioral analyzer."""
        self.logger = logging.getLogger(__name__)
        self.patterns = {}
        
    def analyze_patterns(self, changes: List[Dict]) -> Dict:
        """Analyze behavior patterns in registry changes.
        
        Args:
            changes: List of registry changes
            
        Returns:
            Dictionary with identified patterns
        """
        patterns = {
            'rapid_changes': [],
            'correlated_changes': [],
            'suspicious_sequences': []
        }
        
        try:
            # Detect rapid changes
            time_groups = defaultdict(list)
            for change in changes:
                timestamp = change.get('timestamp', '')
                time_groups[timestamp[:19]].append(change)  # Group by second
            
            for time_key, group in time_groups.items():
                if len(group) > 5:  # More than 5 changes in 1 second
                    patterns['rapid_changes'].append({
                        'time': time_key,
                        'count': len(group),
                        'keys': [c.get('key_path') for c in group]
                    })
            
            # Detect correlated changes
            key_changes = defaultdict(int)
            for change in changes:
                key_changes[change.get('key_path', '')] += 1
            
            for key, count in key_changes.items():
                if count > 10:
                    patterns['correlated_changes'].append({
                        'key': key,
                        'change_count': count
                    })
            
            self.patterns = patterns
            return patterns
            
        except Exception as e:
            self.logger.error(f"Error analyzing patterns: {e}")
            return patterns
