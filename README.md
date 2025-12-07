# Intrusion Detection System (IDS)

A comprehensive, modular Intrusion Detection System capable of real-time network monitoring, signature-based and anomaly-based detection, with a web-based dashboard for visualization and alerting.

## Features

### 🔍 Detection Capabilities

**Signature-Based Detection:**
- SYN Port Scanning
- General Port Scanning
- Suspicious Port Connections
- LAND Attacks
- ICMP Flood Detection

**Anomaly-Based Detection:**
- Denial of Service (DoS) Attack Detection
- Anomalous Traffic Pattern Detection (statistical analysis)
- Large Flow Detection

### 📊 Real-Time Monitoring

- Live packet capture using Scapy
- Real-time alert generation
- Web-based dashboard for visualization
- Statistics and metrics tracking

### 🛠️ Modular Architecture

- **packet_capture.py**: Real-time network packet capture
- **detection_engine.py**: Detection algorithms and rules
- **ids_core.py**: Core orchestrator coordinating all components
- **dashboard.py**: Web dashboard for visualization
- **config.py**: Configuration management
- **run_ids.py**: Main entry point

## Installation

### Prerequisites

- Python 3.8 or higher
- Administrator/root privileges (for packet capture)
- Network interface access

### Install Dependencies

```bash
pip install -r requirements.txt
```

**Note for Windows users:** Scapy may require additional setup. You may need to install Npcap (https://npcap.com/) for packet capture functionality.

**Note for Linux users:** You may need to run with sudo privileges for packet capture:
```bash
sudo pip install -r requirements.txt
```

## Usage

### Basic Usage

Start the IDS with default settings:
```bash
python run_ids.py
```

This will:
1. Start packet capture on the default interface
2. Launch the web dashboard at http://127.0.0.1:5000

### Advanced Usage

**List available network interfaces:**
```bash
python run_ids.py --list-interfaces
```

**Specify a network interface:**
```bash
python run_ids.py --interface eth0
```

**Run dashboard only (no packet capture):**
```bash
python run_ids.py --dashboard-only
```

**Custom dashboard host/port:**
```bash
python run_ids.py --host 0.0.0.0 --port 8080
```

**Use custom configuration file:**
```bash
python run_ids.py --config my_config.json
```

### Configuration

The system uses `ids_config.json` for configuration. On first run, a default configuration file will be created. You can modify:

- Detection thresholds (SYN scan, port scan, DoS, etc.)
- Suspicious ports list
- Output directories
- Dashboard settings

Example configuration:
```json
{
  "detection": {
    "syn_scan_window": 10,
    "syn_scan_threshold": 5,
    "port_scan_window": 60,
    "port_scan_threshold": 10,
    "dos_window": 5,
    "dos_threshold": 100,
    "anomaly_z_threshold": 3.0
  },
  "output_dir": "outputs",
  "dashboard": {
    "host": "127.0.0.1",
    "port": 5000
  }
}
```

## Web Dashboard

Access the dashboard at http://127.0.0.1:5000 (or your configured host/port).

The dashboard provides:
- Real-time status monitoring
- Live alert feed
- Statistics and metrics
- Alert filtering by type and severity
- Start/Stop controls

## Detection Rules

### Port Scanning
- **SYN Scan**: Detects rapid SYN packets to multiple ports from a single source
- **Port Scan**: General port scanning pattern detection

### DoS Attacks
- **DoS Detection**: Detects high packet rates from single source
- **ICMP Flood**: Detects ICMP packet floods

### Anomaly Detection
- **Anomalous Traffic**: Statistical analysis using z-scores to detect unusual packet sizes
- **Large Flows**: Detects unusually large data transfers

### Signature Detection
- **Suspicious Ports**: Alerts on connections to known suspicious ports (Telnet, RDP, etc.)
- **LAND Attack**: Detects packets where source IP = destination IP

## Output Files

All outputs are saved to the `outputs/` directory:

- **alerts.jsonl**: All generated alerts in JSON Lines format
- **statistics.json**: System statistics and metrics

## Architecture

```
┌─────────────────┐
│  Packet Capture │──┐
└─────────────────┘  │
                    ▼
┌─────────────────┐     ┌──────────────┐
│ Detection Engine │────▶│   Alerts    │
└─────────────────┘     └──────────────┘
         │                      │
         ▼                      ▼
┌─────────────────┐     ┌──────────────┐
│   IDS Core      │────▶│  Dashboard   │
└─────────────────┘     └──────────────┘
```

## Development

### Adding New Detection Rules

1. Add detection method to `DetectionEngine` class in `detection_engine.py`
2. Call the method from `process_packet()` method
3. Return alert dictionary with required fields:
   - `type`: Alert type identifier
   - `severity`: HIGH, MEDIUM, or LOW
   - `timestamp`: Detection timestamp
   - `description`: Human-readable description

### Extending the Dashboard

Modify `dashboard.py` to add new routes or update the HTML template for additional visualizations.

## Testing

The IDS can be tested by running it and monitoring real network traffic. For testing in a controlled environment:

1. Start the IDS with the dashboard
2. Generate network traffic (e.g., port scans, large data transfers)
3. Monitor alerts in the dashboard

You can also test specific attack patterns by running network tools that generate the traffic patterns the IDS is designed to detect.

## Security Considerations

- The IDS requires elevated privileges for packet capture
- Run in a controlled environment for testing
- Be aware of privacy implications when monitoring network traffic
- Configure firewall rules appropriately for the dashboard

## Troubleshooting

**"Scapy not available" error:**
- Install Scapy: `pip install scapy`
- On Windows, install Npcap
- On Linux, ensure you have proper permissions

**"Permission denied" for packet capture:**
- Run with sudo (Linux) or as Administrator (Windows)
- Check interface permissions

**Dashboard not accessible:**
- Check firewall settings
- Verify host/port configuration
- Ensure no other service is using the port

## License

This project is provided as-is for educational and research purposes.

## Contributing

Feel free to extend this system with additional detection rules, improved visualizations, or enhanced features.

## Future Enhancements

- Machine learning-based anomaly detection
- Integration with SIEM systems
- Email/SMS alerting
- Packet payload analysis
- Encrypted traffic analysis
- Distributed monitoring capabilities

