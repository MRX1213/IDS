"""
Detection Engine - Signature-based and Anomaly-based Detection
Implements various detection rules for identifying malicious activity
"""
import statistics
from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import json


class DetectionEngine:
    """Main detection engine with multiple detection modules"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.alerts = []
        self.packet_history = deque(maxlen=10000)  # Keep last 10k packets
        self.flow_stats = defaultdict(lambda: {"count": 0, "bytes": 0, "packets": []})
        
        # Detection state
        self.syn_scan_state = defaultdict(lambda: {"packets": deque(), "ports": set()})
        self.dos_state = defaultdict(lambda: {"count": 0, "start_time": None})
        self.port_scan_state = defaultdict(lambda: {"ports": set(), "count": 0, "start_time": None})
        
    def process_packet(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process a single packet and return any alerts"""
        alerts = []
        self.packet_history.append(packet)
        
        # Update flow statistics
        flow_key = (packet.get("src_ip"), packet.get("dst_ip"))
        self.flow_stats[flow_key]["count"] += 1
        self.flow_stats[flow_key]["bytes"] += packet.get("bytes", 0)
        self.flow_stats[flow_key]["packets"].append(packet)
        
        # Run all detection modules
        alerts.extend(self.detect_syn_scan(packet))
        alerts.extend(self.detect_port_scan(packet))
        alerts.extend(self.detect_dos_attack(packet))
        alerts.extend(self.detect_suspicious_ports(packet))
        alerts.extend(self.detect_anomalous_traffic(packet))
        alerts.extend(self.detect_icmp_flood(packet))
        alerts.extend(self.detect_land_attack(packet))
        
        # Store alerts
        for alert in alerts:
            alert["detected_at"] = datetime.now().isoformat()
            self.alerts.append(alert)
        
        return alerts
    
    def detect_syn_scan(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect SYN port scanning (signature-based)"""
        if packet.get("proto") != "TCP":
            return []
        
        flags = packet.get("flags", "")
        if "S" not in flags or "A" in flags:
            return []
        
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        timestamp = packet.get("timestamp")
        
        if not all([src_ip, dst_ip, dst_port, timestamp]):
            return []
        
        key = (src_ip, dst_ip)
        state = self.syn_scan_state[key]
        
        # Add packet to state
        state["packets"].append(packet)
        state["ports"].add(dst_port)
        
        # Remove old packets outside window
        window_seconds = self.config.get("syn_scan_window", 10)
        threshold = self.config.get("syn_scan_threshold", 5)
        
        while state["packets"] and isinstance(timestamp, datetime):
            oldest = state["packets"][0].get("timestamp")
            if isinstance(oldest, datetime) and (timestamp - oldest).total_seconds() > window_seconds:
                removed = state["packets"].popleft()
                # Recalculate ports
                state["ports"] = {p.get("dst_port") for p in state["packets"] if p.get("dst_port")}
            else:
                break
        
        # Check threshold
        if len(state["ports"]) >= threshold:
            alert = {
                "type": "PORT_SCAN_SYN",
                "severity": "HIGH",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "unique_ports": len(state["ports"]),
                "ports_scanned": sorted(list(state["ports"])),
                "window_seconds": window_seconds,
                "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp),
                "description": f"SYN scan detected: {src_ip} scanning {dst_ip} on {len(state["ports"])} ports"
            }
            # Reset state
            state["packets"].clear()
            state["ports"].clear()
            return [alert]
        
        return []
    
    def detect_port_scan(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect general port scanning patterns"""
        if not packet.get("dst_port"):
            return []
        
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        dst_port = packet.get("dst_port")
        timestamp = packet.get("timestamp")
        
        key = (src_ip, dst_ip)
        state = self.port_scan_state[key]
        
        if state["start_time"] is None:
            state["start_time"] = timestamp
        
        state["ports"].add(dst_port)
        state["count"] += 1
        
        window_seconds = self.config.get("port_scan_window", 60)
        threshold = self.config.get("port_scan_threshold", 10)
        
        if isinstance(timestamp, datetime) and isinstance(state["start_time"], datetime):
            elapsed = (timestamp - state["start_time"]).total_seconds()
            if elapsed > window_seconds:
                # Reset window
                state["ports"].clear()
                state["count"] = 0
                state["start_time"] = timestamp
            elif len(state["ports"]) >= threshold:
                alert = {
                    "type": "PORT_SCAN",
                    "severity": "MEDIUM",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "unique_ports": len(state["ports"]),
                    "total_packets": state["count"],
                    "window_seconds": window_seconds,
                    "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp),
                    "description": f"Port scan detected: {src_ip} -> {dst_ip} ({len(state["ports"])} ports)"
                }
                # Reset
                state["ports"].clear()
                state["count"] = 0
                state["start_time"] = timestamp
                return [alert]
        
        return []
    
    def detect_dos_attack(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect Denial of Service attacks (anomaly-based)"""
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        timestamp = packet.get("timestamp")
        
        key = (src_ip, dst_ip)
        state = self.dos_state[key]
        
        if state["start_time"] is None:
            state["start_time"] = timestamp
        
        state["count"] += 1
        
        window_seconds = self.config.get("dos_window", 5)
        threshold = self.config.get("dos_threshold", 100)
        
        if isinstance(timestamp, datetime) and isinstance(state["start_time"], datetime):
            elapsed = (timestamp - state["start_time"]).total_seconds()
            if elapsed > window_seconds:
                # Reset window
                state["count"] = 0
                state["start_time"] = timestamp
            elif state["count"] >= threshold:
                alert = {
                    "type": "DOS_ATTACK",
                    "severity": "HIGH",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "packet_count": state["count"],
                    "window_seconds": window_seconds,
                    "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp),
                    "description": f"DoS attack detected: {src_ip} -> {dst_ip} ({state["count"]} packets in {window_seconds}s)"
                }
                # Reset
                state["count"] = 0
                state["start_time"] = timestamp
                return [alert]
        
        return []
    
    def detect_suspicious_ports(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect connections to suspicious ports (signature-based)"""
        dst_port = packet.get("dst_port")
        if not dst_port:
            return []
        
        # Common suspicious ports
        suspicious_ports = self.config.get("suspicious_ports", {
            23: "Telnet (unencrypted)",
            135: "RPC",
            139: "NetBIOS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            8080: "HTTP Proxy"
        })
        
        if dst_port in suspicious_ports:
            return [{
                "type": "SUSPICIOUS_PORT",
                "severity": "MEDIUM",
                "src_ip": packet.get("src_ip"),
                "dst_ip": packet.get("dst_ip"),
                "dst_port": dst_port,
                "port_description": suspicious_ports[dst_port],
                "timestamp": packet.get("timestamp").isoformat() if isinstance(packet.get("timestamp"), datetime) else str(packet.get("timestamp")),
                "description": f"Connection to suspicious port {dst_port} ({suspicious_ports[dst_port]})"
            }]
        
        return []
    
    def detect_anomalous_traffic(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect anomalous traffic patterns using statistical analysis (anomaly-based)"""
        if len(self.packet_history) < 100:
            return []  # Need baseline
        
        # Get recent packet sizes
        recent_sizes = [p.get("bytes", 0) for p in list(self.packet_history)[-100:]]
        
        if len(recent_sizes) < 2:
            return []
        
        mean = statistics.mean(recent_sizes)
        stdev = statistics.pstdev(recent_sizes) if len(recent_sizes) > 1 else 0
        
        if stdev == 0:
            return []
        
        packet_size = packet.get("bytes", 0)
        z_score = (packet_size - mean) / stdev
        
        z_threshold = self.config.get("anomaly_z_threshold", 3.0)
        
        if z_score >= z_threshold:
            return [{
                "type": "ANOMALOUS_TRAFFIC",
                "severity": "MEDIUM",
                "src_ip": packet.get("src_ip"),
                "dst_ip": packet.get("dst_ip"),
                "packet_size": packet_size,
                "z_score": round(z_score, 2),
                "mean_size": round(mean, 2),
                "std_dev": round(stdev, 2),
                "timestamp": packet.get("timestamp").isoformat() if isinstance(packet.get("timestamp"), datetime) else str(packet.get("timestamp")),
                "description": f"Anomalously large packet detected (z-score: {z_score:.2f})"
            }]
        
        return []
    
    def detect_icmp_flood(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect ICMP flood attacks"""
        if packet.get("proto") != "ICMP":
            return []
        
        src_ip = packet.get("src_ip")
        timestamp = packet.get("timestamp")
        
        # Count ICMP packets from source
        key = f"icmp_{src_ip}"
        state = self.dos_state[key]  # Reuse DOS state structure
        
        if state["start_time"] is None:
            state["start_time"] = timestamp
        
        state["count"] += 1
        
        window_seconds = self.config.get("icmp_flood_window", 10)
        threshold = self.config.get("icmp_flood_threshold", 50)
        
        if isinstance(timestamp, datetime) and isinstance(state["start_time"], datetime):
            elapsed = (timestamp - state["start_time"]).total_seconds()
            if elapsed > window_seconds:
                state["count"] = 0
                state["start_time"] = timestamp
            elif state["count"] >= threshold:
                alert = {
                    "type": "ICMP_FLOOD",
                    "severity": "HIGH",
                    "src_ip": src_ip,
                    "packet_count": state["count"],
                    "window_seconds": window_seconds,
                    "timestamp": timestamp.isoformat() if isinstance(timestamp, datetime) else str(timestamp),
                    "description": f"ICMP flood detected from {src_ip} ({state["count"]} packets)"
                }
                state["count"] = 0
                state["start_time"] = timestamp
                return [alert]
        
        return []
    
    def detect_land_attack(self, packet: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Detect LAND attack (source IP = destination IP)"""
        src_ip = packet.get("src_ip")
        dst_ip = packet.get("dst_ip")
        
        if src_ip and dst_ip and src_ip == dst_ip:
            return [{
                "type": "LAND_ATTACK",
                "severity": "HIGH",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": packet.get("timestamp").isoformat() if isinstance(packet.get("timestamp"), datetime) else str(packet.get("timestamp")),
                "description": f"LAND attack detected: source and destination IP are the same ({src_ip})"
            }]
        
        return []
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detection statistics"""
        return {
            "total_packets_processed": len(self.packet_history),
            "total_alerts": len(self.alerts),
            "alerts_by_type": self._count_alerts_by_type(),
            "alerts_by_severity": self._count_alerts_by_severity(),
            "recent_alerts": self.alerts[-10:] if len(self.alerts) > 0 else []
        }
    
    def _count_alerts_by_type(self) -> Dict[str, int]:
        """Count alerts by type"""
        counts = defaultdict(int)
        for alert in self.alerts:
            counts[alert.get("type", "UNKNOWN")] += 1
        return dict(counts)
    
    def _count_alerts_by_severity(self) -> Dict[str, int]:
        """Count alerts by severity"""
        counts = defaultdict(int)
        for alert in self.alerts:
            counts[alert.get("severity", "UNKNOWN")] += 1
        return dict(counts)
    
    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent alerts"""
        return self.alerts[-limit:] if len(self.alerts) > 0 else []
    
    def clear_alerts(self):
        """Clear all alerts"""
        self.alerts.clear()

