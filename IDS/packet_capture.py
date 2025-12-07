"""
Real-time Network Packet Capture Module
Captures network packets using Scapy and converts them to a standardized format
"""
import threading
import queue
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
import json

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, get_if_list
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    print("Warning: Scapy not available. Install with: pip install scapy")


class PacketCapture:
    """Real-time packet capture using Scapy"""
    
    def __init__(self, interface: Optional[str] = None, packet_queue: Optional[queue.Queue] = None):
        self.interface = interface
        self.packet_queue = packet_queue or queue.Queue(maxsize=1000)
        self.capturing = False
        self.capture_thread = None
        self.packet_count = 0
        
    def _packet_handler(self, packet):
        """Process captured packet and convert to standard format"""
        try:
            if not packet.haslayer(IP):
                return
                
            ip_layer = packet[IP]
            timestamp = datetime.now()
            
            # Extract basic info
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            proto = ip_layer.proto
            proto_name = "UNKNOWN"
            src_port = None
            dst_port = None
            flags = ""
            payload_size = 0
            
            # Extract protocol-specific info
            if packet.haslayer(TCP):
                proto_name = "TCP"
                tcp_layer = packet[TCP]
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                flags = self._extract_tcp_flags(tcp_layer.flags)
                if packet.haslayer(Raw):
                    payload_size = len(packet[Raw].load)
                else:
                    payload_size = len(bytes(tcp_layer.payload))
            elif packet.haslayer(UDP):
                proto_name = "UDP"
                udp_layer = packet[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                if packet.haslayer(Raw):
                    payload_size = len(packet[Raw].load)
            elif packet.haslayer(ICMP):
                proto_name = "ICMP"
                icmp_layer = packet[ICMP]
                payload_size = len(bytes(icmp_layer.payload))
            
            # Total packet size
            total_bytes = len(packet)
            
            # Create standardized packet dict
            packet_data = {
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": proto_name,
                "bytes": total_bytes,
                "payload_bytes": payload_size,
                "flags": flags,
                "raw_packet": packet.summary() if hasattr(packet, 'summary') else str(packet)
            }
            
            self.packet_count += 1
            if self.packet_queue:
                try:
                    self.packet_queue.put_nowait(packet_data)
                except queue.Full:
                    # Queue full, drop oldest packet
                    try:
                        self.packet_queue.get_nowait()
                        self.packet_queue.put_nowait(packet_data)
                    except queue.Empty:
                        pass
                        
        except Exception as e:
            print(f"Error processing packet: {e}")
    
    def _extract_tcp_flags(self, flags_value):
        """Extract TCP flags as string"""
        flags = []
        if flags_value & 0x01: flags.append("F")  # FIN
        if flags_value & 0x02: flags.append("S")  # SYN
        if flags_value & 0x04: flags.append("R")  # RST
        if flags_value & 0x08: flags.append("P")  # PSH
        if flags_value & 0x10: flags.append("A")  # ACK
        if flags_value & 0x20: flags.append("U")  # URG
        return "".join(flags)
    
    def start_capture(self, count: int = 0, timeout: Optional[int] = None):
        """Start capturing packets in a separate thread"""
        if not SCAPY_AVAILABLE:
            raise RuntimeError("Scapy is not available. Install with: pip install scapy")
        
        if self.capturing:
            print("Capture already running")
            return
        
        self.capturing = True
        self.packet_count = 0
        
        def capture_loop():
            try:
                sniff(
                    iface=self.interface,
                    prn=self._packet_handler,
                    count=count,
                    timeout=timeout,
                    stop_filter=lambda x: not self.capturing
                )
            except Exception as e:
                print(f"Capture error: {e}")
            finally:
                self.capturing = False
        
        self.capture_thread = threading.Thread(target=capture_loop, daemon=True)
        self.capture_thread.start()
        print(f"Started packet capture on interface: {self.interface or 'default'}")
    
    def stop_capture(self):
        """Stop capturing packets"""
        self.capturing = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2)
        print(f"Stopped packet capture. Total packets: {self.packet_count}")
    
    def get_packet(self, timeout: float = 1.0) -> Optional[Dict[str, Any]]:
        """Get next packet from queue"""
        try:
            return self.packet_queue.get(timeout=timeout)
        except queue.Empty:
            return None
    
    @staticmethod
    def list_interfaces():
        """List available network interfaces"""
        if not SCAPY_AVAILABLE:
            return []
        try:
            return get_if_list()
        except:
            return []

