# Windows Registry Monitor


![Python Version](https://img.shields.io/badge/python-3.8%2B-blue) ![GitHub Actions](https://github.com/gauravmalhotra3300-hub/windows-registry-monitor/workflows/Python%20CI/CD/badge.svg) ![License](https://img.shields.io/badge/license-MIT-green) ![Status](https://img.shields.io/badge/status-stable-brightgreen)
A comprehensive Windows Registry monitoring system for detecting unauthorized registry modifications, malware persistence mechanisms, and suspicious system changes. This project provides a complete defensive security toolkit for registry auditing, baseline comparison, real-time alerting, and forensic reporting.

## Features

### Core Capabilities
- **Real-time Registry Monitoring**: Continuous polling and monitoring of sensitive Windows Registry keys
- **Baseline Creation & Comparison**: Create initial registry snapshots and detect deviations from baseline
- **Malware Detection Patterns**: Identify known malware behavior patterns including:
  - Windows Defender tampering attempts
  - Persistence mechanisms (autorun entries)
  - Shell and system startup modifications
  - UAC bypass attempts
  - Network configuration hijacking
- **Comprehensive Alerting System**: Multi-level risk alerts (CRITICAL, HIGH, MEDIUM, LOW)
- **Advanced Reporting**: Multiple output formats (JSON, CSV, HTML) with forensic analysis
- **Registry Integrity Verification**: SHA256-based integrity checking of baseline snapshots

### Monitoring Coverage
- User and system autorun keys
- Windows Defender security settings
- System policies and group policies
- Critical startup locations
- Security tool configurations

## Project Structure

```
windows-registry-monitor/
├── src/                          # Source code directory
│   ├── __init__.py              # Package initialization
│   ├── registry_monitor.py       # Core registry monitoring module
│   ├── baseline_manager.py       # Baseline snapshot management
│   ├── alert_system.py          # Alert generation and analysis
│   └── report_generator.py      # Report generation (JSON, CSV, HTML)
├── main.py                       # Application entry point
├── README.md                     # This file
└── .gitignore                   # Python gitignore template
```

## Installation

### Requirements
- Windows 10/11 or Windows Server 2016+
- Python 3.7+
- Administrator privileges (for reading registry)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/gauravmalhotra3300-hub/windows-registry-monitor.git
cd windows-registry-monitor
```

2. Create directories for logs and reports:
```bash
mkdir logs
mkdir reports
mkdir baselines
```

3. No external dependencies required - uses Python standard library (winreg, json, csv, etc.)

## Usage

### Basic Execution

```bash
python main.py
```

### Module Components

#### 1. Registry Monitor (registry_monitor.py)
Monitors Windows Registry for changes and suspicious modifications.

**Key Methods:**
- `capture_registry_state()`: Takes a snapshot of sensitive registry keys
- `detect_changes(previous_snapshot)`: Identifies additions, modifications, deletions
- `monitor_registry(previous_snapshot)`: Main monitoring workflow

#### 2. Baseline Manager (baseline_manager.py)
Handles baseline creation, storage, and verification.

**Key Methods:**
- `create_baseline()`: Creates initial registry snapshot
- `load_baseline()`: Loads existing baseline from file
- `verify_baseline_integrity()`: SHA256-based integrity checking
- `get_baseline_snapshot()`: Retrieves baseline data

#### 3. Alert System (alert_system.py)
Analyzes registry changes and generates security alerts.

**Alert Types:**
- `SECURITY_THREAT`: Windows Defender or security software tampering
- `PERSISTENCE_MECHANISM`: Suspicious autorun entries
- `SYSTEM_MODIFICATION`: Shell or startup location changes
- `PRIVILEGE_ESCALATION`: UAC bypass attempts
- `SUSPICIOUS_VALUE`: Unusually large or suspicious values

#### 4. Report Generator (report_generator.py)
Generates comprehensive monitoring reports in multiple formats.

**Output Formats:**
- **JSON Report**: Complete data with metadata and summary statistics
- **CSV Report**: Detailed change log for analysis
- **HTML Report**: Visual summary with statistics and top changes

## Workflow

```
START
  ↓

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue) ![GitHub Actions](https://github.com/gauravmalhotra3300-hub/windows-registry-monitor/workflows/Python%20CI/CD/badge.svg) ![License](https://img.shields.io/badge/license-MIT-green) ![Status](https://img.shields.io/badge/status-stable-brightgreen)
Load Configuration
  ↓
Create/Load Baseline Registry Snapshot
  ↓
Monitor Registry Keys at Intervals
  ↓
Detect Changes (Add/Modify/Delete)
  ↓
Compare with Malware Behavior Patterns
  ↓
Generate Alerts + Logs
  ↓
Export Reports (JSON/CSV/HTML)
  ↓
END
```

## Output Examples

### Alert Output
```json
{
  "type": "PERSISTENCE_MECHANISM",
  "title": "Suspicious Autorun Entry Detected",
  "description": "New autorun entry added: malware.exe",
  "risk_level": "HIGH",
  "key_path": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
  "value_name": "MalwareName",
  "timestamp": "2026-01-02T20:30:45.123456"
}
```

### Report Summary
```json
{
  "report_metadata": {
    "generated_at": "2026-01-02T20:30:45",
    "total_changes": 15,
    "total_alerts": 3
  },
  "summary": {
    "changes_summary": {"NEW": 5, "MODIFIED": 8, "DELETED": 2},
    "critical_alerts": 1,
    "high_alerts": 2
  }
}
```

## Security Features

1. **Baseline Integrity**: SHA256 hashing ensures baseline hasn't been tampered with
2. **Comprehensive Logging**: All operations logged with timestamps for forensic analysis
3. **Risk-Based Alerting**: Multi-level alert system for prioritized response
4. **Registry Forensics**: Detailed change tracking with before/after values
5. **Blue Team Techniques**: Implements industry-standard monitoring practices

## Monitored Registry Paths

- `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` (User autorun)
- `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` (System autorun)
- `HKLM\Software\Microsoft\Windows Defender` (Security settings)
- `HKLM\Software\Policies\Microsoft\Windows Defender` (Defender policies)
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies` (User policies)

## Learning Outcomes

This project teaches:
- Windows Registry structure and key categories
- How malware persists via registry modifications
- How defenders monitor unauthorized changes
- Practical registry scripting and auditing
- Building endpoint monitoring systems
- Forensic analysis and change tracking

## Use Cases

1. **Security Operations Center (SOC)**: Monitor for unauthorized system changes
2. **Incident Response**: Investigate compromised systems
3. **Digital Forensics**: Analyze system modification history
4. **Compliance**: Verify system integrity against policies
5. **Threat Detection**: Identify malware installation attempts

## Limitations

- Requires administrator privileges
- Windows-only (requires Windows Registry access)
- Monitoring interval affects real-time detection capability
- Large registry keys may impact performance

## Future Enhancements

- Real-time Windows Registry change notifications (WMI/ETW integration)
- Webhook integration for alert notifications
- Database backend for historical analysis
- Machine learning for anomaly detection
- Distributed monitoring across multiple systems
- Integration with SIEM platforms

## References

- [Windows Registry Structure](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry)
- [Malware Persistence Techniques](https://attack.mitre.org/)
- [Python winreg Documentation](https://docs.python.org/3/library/winreg.html)

## Author

Cybersecurity Team

## License

MIT License - See LICENSE file for details

## Disclaimer

This tool is designed for authorized security testing and defensive monitoring only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before using this tool.
