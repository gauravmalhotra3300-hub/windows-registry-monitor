#!/usr/bin/env python3
"""
Windows Registry Change Monitoring System
Main entry point for the registry monitoring application.
"""

import os
import sys
import logging
from datetime import datetime

# Add src directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from registry_monitor import RegistryMonitor
from baseline_manager import BaselineManager
from alert_system import AlertSystem
from report_generator import ReportGenerator

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/registry_monitor.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def main():
    """
    Main function to orchestrate registry monitoring workflow.
    """
    logger.info("=" * 80)
    logger.info("Windows Registry Change Monitoring System Started")
    logger.info(f"Timestamp: {datetime.now().isoformat()}")
    logger.info("=" * 80)
    
    try:
        # Initialize components
        baseline_mgr = BaselineManager()
        monitor = RegistryMonitor()
        alert_system = AlertSystem()
        report_gen = ReportGenerator()
        
        # Create or load baseline
        if not baseline_mgr.baseline_exists():
            logger.info("Creating initial registry baseline...")
            baseline_mgr.create_baseline()
        else:
            logger.info("Loading existing registry baseline...")
            baseline_mgr.load_baseline()
        
        # Start monitoring
        logger.info("Starting registry monitoring...")
        changes = monitor.monitor_registry()
        
        if changes:
            logger.info(f"Detected {len(changes)} registry changes")
            
            # Generate alerts
            alerts = alert_system.analyze_changes(changes)
            if alerts:
                alert_system.send_alerts(alerts)
            
            # Generate report
            report_gen.generate_report(changes, alerts)
        else:
            logger.info("No registry changes detected")
        
        logger.info("Registry monitoring completed successfully")
        
    except Exception as e:
        logger.error(f"Error during monitoring: {str(e)}", exc_info=True)
        sys.exit(1)

if __name__ == "__main__":
    main()
