"""
Core IDS Orchestrator
Coordinates packet capture, detection, and alerting
"""
import threading
import time
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any, Callable
from queue import Queue

from packet_capture import PacketCapture
from detection_engine import DetectionEngine


class IDSCore:
    """Main IDS orchestrator"""
    
    def __init__(self, config: Optional[Dict] = None, interface: Optional[str] = None):
        self.config = config or {}
        self.interface = interface
        self.running = False
        
        # Components
        self.packet_queue = Queue(maxsize=1000)
        self.packet_capture = PacketCapture(interface=interface, packet_queue=self.packet_queue)
        self.detection_engine = DetectionEngine(config=self.config.get("detection", {}))
        
        # Statistics
        self.stats = {
            "packets_processed": 0,
            "alerts_generated": 0,
            "start_time": None,
            "uptime_seconds": 0
        }
        
        # Alert callback
        self.alert_callback: Optional[Callable] = None
        
        # Output directory
        self.output_dir = Path(self.config.get("output_dir", "outputs"))
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
    def set_alert_callback(self, callback: Callable):
        """Set callback function for when alerts are generated"""
        self.alert_callback = callback
    
    def start(self):
        """Start the IDS"""
        if self.running:
            print("IDS is already running")
            return
        
        self.running = True
        self.stats["start_time"] = datetime.now()
        
        # Start packet capture
        self.packet_capture.start_capture()
        
        # Start processing thread
        self.processing_thread = threading.Thread(target=self._processing_loop, daemon=True)
        self.processing_thread.start()
        
        print("IDS started successfully")
        print(f"Monitoring interface: {self.interface or 'default'}")
        print(f"Output directory: {self.output_dir}")
    
    def stop(self):
        """Stop the IDS"""
        if not self.running:
            return
        
        self.running = False
        self.packet_capture.stop_capture()
        
        if hasattr(self, 'processing_thread'):
            self.processing_thread.join(timeout=5)
        
        # Save final statistics
        self._save_statistics()
        
        print("IDS stopped")
    
    def _processing_loop(self):
        """Main processing loop"""
        while self.running:
            try:
                # Get packet from queue
                packet = self.packet_capture.get_packet(timeout=0.5)
                
                if packet:
                    # Process packet through detection engine
                    alerts = self.detection_engine.process_packet(packet)
                    
                    # Update statistics
                    self.stats["packets_processed"] += 1
                    self.stats["alerts_generated"] += len(alerts)
                    
                    # Handle alerts
                    for alert in alerts:
                        self._handle_alert(alert)
                
                # Update uptime
                if self.stats["start_time"]:
                    self.stats["uptime_seconds"] = (datetime.now() - self.stats["start_time"]).total_seconds()
                
            except Exception as e:
                print(f"Error in processing loop: {e}")
                time.sleep(1)
    
    def _handle_alert(self, alert: Dict[str, Any]):
        """Handle a generated alert"""
        # Save to file
        self._save_alert(alert)
        
        # Call callback if set
        if self.alert_callback:
            try:
                self.alert_callback(alert)
            except Exception as e:
                print(f"Error in alert callback: {e}")
        
        # Print alert
        print(f"[ALERT] {alert.get('type')} - {alert.get('severity')}: {alert.get('description', '')}")
    
    def _save_alert(self, alert: Dict[str, Any]):
        """Save alert to JSONL file"""
        alerts_file = self.output_dir / "alerts.jsonl"
        try:
            with alerts_file.open("a", encoding="utf-8") as f:
                f.write(json.dumps(alert, default=str) + "\n")
        except Exception as e:
            print(f"Error saving alert: {e}")
    
    def _save_statistics(self):
        """Save statistics to file"""
        stats_file = self.output_dir / "statistics.json"
        try:
            stats_data = {
                **self.stats,
                "detection_stats": self.detection_engine.get_statistics(),
                "timestamp": datetime.now().isoformat()
            }
            with stats_file.open("w", encoding="utf-8") as f:
                json.dump(stats_data, f, indent=2, default=str)
        except Exception as e:
            print(f"Error saving statistics: {e}")
    
    def get_status(self) -> Dict[str, Any]:
        """Get current IDS status"""
        return {
            "running": self.running,
            "stats": self.stats,
            "detection_stats": self.detection_engine.get_statistics(),
            "packet_capture_stats": {
                "capturing": self.packet_capture.capturing,
                "packets_captured": self.packet_capture.packet_count
            }
        }
    
    def get_recent_alerts(self, limit: int = 50) -> list:
        """Get recent alerts"""
        return self.detection_engine.get_recent_alerts(limit)
    
    def get_alerts_by_type(self, alert_type: str) -> list:
        """Get alerts of a specific type"""
        return [a for a in self.detection_engine.alerts if a.get("type") == alert_type]
    
    def get_alerts_by_severity(self, severity: str) -> list:
        """Get alerts of a specific severity"""
        return [a for a in self.detection_engine.alerts if a.get("severity") == severity]

