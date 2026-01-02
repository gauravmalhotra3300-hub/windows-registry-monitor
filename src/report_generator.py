#!/usr/bin/env python3
"""
Report Generator Module
Generates comprehensive registry monitoring reports.
"""

import json
import logging
import csv
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class ReportGenerator:
    """Generate detailed reports of registry changes and alerts."""
    
    def __init__(self, report_dir: str = "reports"):
        """Initialize report generator with output directory."""
        self.report_dir = Path(report_dir)
        self.report_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_report(self, changes: List[Dict[str, Any]], 
                       alerts: List[Dict[str, Any]] = None) -> bool:
        """
        Generate comprehensive monitoring report.
        
        Args:
            changes: List of registry changes
            alerts: List of generated alerts
        
        Returns:
            True if report generated successfully
        """
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Generate JSON report
            json_report = self._generate_json_report(changes, alerts)
            json_file = self.report_dir / f"registry_report_{timestamp}.json"
            self._save_json_report(json_file, json_report)
            
            # Generate CSV report
            csv_file = self.report_dir / f"registry_changes_{timestamp}.csv"
            self._generate_csv_report(csv_file, changes)
            
            # Generate HTML summary
            html_file = self.report_dir / f"registry_summary_{timestamp}.html"
            self._generate_html_report(html_file, changes, alerts)
            
            logger.info(f"Reports generated in {self.report_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate report: {str(e)}")
            return False
    
    def _generate_json_report(self, changes: List[Dict[str, Any]], 
                             alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate JSON format report.
        
        Args:
            changes: Registry changes list
            alerts: Alerts list
        
        Returns:
            Dictionary with report data
        """
        return {
            'report_metadata': {
                'generated_at': datetime.now().isoformat(),
                'total_changes': len(changes),
                'total_alerts': len(alerts) if alerts else 0
            },
            'changes': changes,
            'alerts': alerts if alerts else [],
            'summary': self._generate_summary(changes, alerts)
        }
    
    def _generate_summary(self, changes: List[Dict[str, Any]], 
                         alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics.
        
        Args:
            changes: Registry changes
            alerts: Generated alerts
        
        Returns:
            Summary dictionary
        """
        change_types = {'NEW': 0, 'MODIFIED': 0, 'DELETED': 0}
        critical_alerts = 0
        high_alerts = 0
        
        for change in changes:
            change_type = change.get('type', 'UNKNOWN')
            if change_type in change_types:
                change_types[change_type] += 1
        
        if alerts:
            for alert in alerts:
                risk = alert.get('risk_level', '')
                if risk == 'CRITICAL':
                    critical_alerts += 1
                elif risk == 'HIGH':
                    high_alerts += 1
        
        return {
            'changes_summary': change_types,
            'critical_alerts': critical_alerts,
            'high_alerts': high_alerts,
            'timestamp': datetime.now().isoformat()
        }
    
    def _save_json_report(self, filepath: Path, data: Dict[str, Any]) -> None:
        """
        Save JSON report to file.
        
        Args:
            filepath: Path to save report
            data: Report data
        """
        try:
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            logger.info(f"JSON report saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save JSON report: {str(e)}")
    
    def _generate_csv_report(self, filepath: Path, 
                            changes: List[Dict[str, Any]]) -> None:
        """
        Generate CSV format change log.
        
        Args:
            filepath: Path to save CSV file
            changes: Registry changes
        """
        try:
            if not changes:
                logger.info("No changes to report")
                return
            
            with open(filepath, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=[
                    'timestamp', 'type', 'key_path', 'value_name', 
                    'old_value', 'new_value'
                ])
                writer.writeheader()
                
                for change in changes:
                    writer.writerow({
                        'timestamp': change.get('timestamp', ''),
                        'type': change.get('type', ''),
                        'key_path': change.get('key_path', ''),
                        'value_name': change.get('value_name', ''),
                        'old_value': str(change.get('old_value', '')),
                        'new_value': str(change.get('new_value', ''))
                    })
            
            logger.info(f"CSV report saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to save CSV report: {str(e)}")
    
    def _generate_html_report(self, filepath: Path, 
                             changes: List[Dict[str, Any]], 
                             alerts: List[Dict[str, Any]]) -> None:
        """
        Generate HTML summary report.
        
        Args:
            filepath: Path to save HTML file
            changes: Registry changes
            alerts: Alerts
        """
        try:
            summary = self._generate_summary(changes, alerts)
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>Registry Monitoring Report</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 20px; }}
                    h1 {{ color: #333; }}
                    .summary {{ background: #f0f0f0; padding: 15px; border-radius: 5px; }}
                    .stats {{ display: flex; gap: 20px; margin-top: 15px; }}
                    .stat {{ background: white; padding: 10px; border-radius: 3px; }}
                    .critical {{ color: red; font-weight: bold; }}
                    .high {{ color: orange; font-weight: bold; }}
                    table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #4CAF50; color: white; }}
                </style>
            </head>
            <body>
                <h1>Windows Registry Monitoring Report</h1>
                <p>Generated: {datetime.now().isoformat()}</p>
                
                <div class="summary">
                    <h2>Summary</h2>
                    <div class="stats">
                        <div class="stat">New Entries: {summary['changes_summary']['NEW']}</div>
                        <div class="stat">Modified Entries: {summary['changes_summary']['MODIFIED']}</div>
                        <div class="stat">Deleted Entries: {summary['changes_summary']['DELETED']}</div>
                        <div class="stat critical">Critical Alerts: {summary['critical_alerts']}</div>
                        <div class="stat high">High Alerts: {summary['high_alerts']}</div>
                    </div>
                </div>
                
                <h2>Top Registry Changes</h2>
                <table>
                    <tr>
                        <th>Type</th>
                        <th>Key Path</th>
                        <th>Value Name</th>
                        <th>Timestamp</th>
                    </tr>
            """
            
            for change in changes[:10]:  # Top 10 changes
                html_content += f"""
                    <tr>
                        <td>{change.get('type', '')}</td>
                        <td>{change.get('key_path', '')}</td>
                        <td>{change.get('value_name', '')}</td>
                        <td>{change.get('timestamp', '')}</td>
                    </tr>
                """
            
            html_content += """
                </table>
            </body>
            </html>
            """
            
            with open(filepath, 'w') as f:
                f.write(html_content)
            
            logger.info(f"HTML report saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {str(e)}")
