# Quick Start Guide

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

**Note:** On Windows, you may need to install [Npcap](https://npcap.com/) for packet capture.

## Running the IDS

### Option 1: Full IDS with Dashboard (Recommended)

```bash
python run_ids.py
```

Then open your browser to: http://127.0.0.1:5000

### Option 2: List Available Interfaces

```bash
python run_ids.py --list-interfaces
```

### Option 3: Specify Interface

```bash
python run_ids.py --interface eth0
```

On Windows, you might use:
```bash
python run_ids.py --interface "Ethernet"
```

### Option 4: Dashboard Only (for testing)

```bash
python run_ids.py --dashboard-only
```

## Testing

The IDS monitors real-time network traffic. To test it:

1. Start the IDS: `python run_ids.py`
2. Generate network traffic (e.g., using network tools or normal browsing)
3. Monitor the dashboard for alerts

For testing specific attack patterns, you can use network scanning tools or generate traffic that matches the detection rules.

## Configuration

The first time you run the IDS, it will create `ids_config.json` with default settings. You can modify this file to adjust:

- Detection thresholds
- Suspicious ports
- Dashboard settings
- Output directories

## Dashboard Features

- **Real-time Monitoring**: See packets processed and alerts generated
- **Live Alerts**: View recent security alerts with severity levels
- **Statistics**: View alerts by type and severity
- **Controls**: Start/Stop IDS from the dashboard

## Common Issues

**"Scapy not available"**
- Install: `pip install scapy`
- Windows: Install Npcap from https://npcap.com/

**"Permission denied"**
- Linux: Run with `sudo`
- Windows: Run as Administrator

**Dashboard not loading**
- Check if port 5000 is available
- Try: `python run_ids.py --port 8080`

## Next Steps

- Review `README.md` for detailed documentation
- Customize detection rules in `detection_engine.py`
- Modify dashboard appearance in `dashboard.py`

