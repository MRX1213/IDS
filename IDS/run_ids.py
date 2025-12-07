"""
Main Entry Point for IDS
Run this script to start the Intrusion Detection System with web dashboard
"""
import argparse
import signal
import sys
from pathlib import Path

from config import IDSConfig
from ids_core import IDSCore
from dashboard import IDSDashboard
from packet_capture import PacketCapture


def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully"""
    print("\n\nShutting down IDS...")
    if 'ids' in globals():
        ids.stop()
    sys.exit(0)


def list_interfaces():
    """List available network interfaces"""
    interfaces = PacketCapture.list_interfaces()
    if interfaces:
        print("Available network interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")
    else:
        print("No interfaces found or Scapy not available")
    return interfaces


def main():
    parser = argparse.ArgumentParser(description="Intrusion Detection System")
    parser.add_argument("--interface", "-i", type=str, help="Network interface to monitor (default: auto-detect)")
    parser.add_argument("--config", "-c", type=str, help="Path to configuration file")
    parser.add_argument("--dashboard-only", action="store_true", help="Run dashboard only (no packet capture)")
    parser.add_argument("--list-interfaces", action="store_true", help="List available network interfaces")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Dashboard host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5000, help="Dashboard port (default: 5000)")
    
    args = parser.parse_args()
    
    # Handle list interfaces
    if args.list_interfaces:
        list_interfaces()
        return
    
    # Load configuration
    config_file = Path(args.config) if args.config else None
    config = IDSConfig(config_file)
    
    # Setup signal handler
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Create IDS core
    interface = args.interface
    if not interface and not args.dashboard_only:
        # Try to auto-detect interface
        interfaces = PacketCapture.list_interfaces()
        if interfaces:
            interface = interfaces[0]
            print(f"Auto-selected interface: {interface}")
        else:
            print("Warning: No interface specified and none detected. Use --list-interfaces to see available interfaces.")
            print("Running in dashboard-only mode. Use --interface to specify an interface for packet capture.")
            args.dashboard_only = True
    
    global ids
    ids = IDSCore(config=config.config, interface=interface)
    
    # Start IDS if not dashboard-only
    if not args.dashboard_only:
        try:
            ids.start()
            print("IDS started successfully!")
        except Exception as e:
            print(f"Error starting IDS: {e}")
            print("Continuing with dashboard only...")
    
    # Create and run dashboard
    dashboard_host = args.host or config.get("dashboard.host", "127.0.0.1")
    dashboard_port = args.port or config.get("dashboard.port", 5000)
    
    dashboard = IDSDashboard(ids, host=dashboard_host, port=dashboard_port)
    
    try:
        dashboard.run(debug=False)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()

