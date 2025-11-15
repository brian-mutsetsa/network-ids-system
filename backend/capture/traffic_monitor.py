"""
Simple Network Traffic Monitor
Captures packets from your network and displays them
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP, conf
from datetime import datetime
import sys

class TrafficMonitor:
    """Captures and displays network traffic"""
    
    def __init__(self, interface=None):
        """
        Initialize the traffic monitor
        
        Args:
            interface: Network interface to monitor (None = auto-detect)
        """
        self.interface = interface
        self.packet_count = 0
        self.packets_captured = []
        
        print("=" * 60)
        print("🔍 Network Traffic Monitor Starting...")
        print("=" * 60)
        
        # Show available interfaces
        if interface is None:
            print("\n📡 Auto-detecting network interface...")
            self.interface = conf.iface
            print(f"✓ Using interface: {self.interface}")
        else:
            print(f"✓ Using specified interface: {self.interface}")
    
    def packet_callback(self, packet):
        """
        This function is called for EVERY packet captured
        
        Args:
            packet: The captured network packet
        """
        self.packet_count += 1
        
        # Only process packets with IP layer
        if IP in packet:
            packet_info = self._extract_info(packet)
            self.packets_captured.append(packet_info)
            self._display_packet(packet_info)
    
    def _extract_info(self, packet):
        """
        Extract useful information from a packet
        
        Returns:
            Dictionary with packet details
        """
        info = {
            'number': self.packet_count,
            'timestamp': datetime.now().strftime('%H:%M:%S'),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'length': len(packet),
            'protocol': 'Unknown'
        }
        
        # Determine protocol
        if TCP in packet:
            info['protocol'] = 'TCP'
            info['src_port'] = packet[TCP].sport
            info['dst_port'] = packet[TCP].dport
        elif UDP in packet:
            info['protocol'] = 'UDP'
            info['src_port'] = packet[UDP].sport
            info['dst_port'] = packet[UDP].dport
        elif ICMP in packet:
            info['protocol'] = 'ICMP'
            info['src_port'] = '-'
            info['dst_port'] = '-'
        
        return info
    
    def _display_packet(self, info):
        """Display packet information in a nice format"""
        print(f"\n[Packet #{info['number']}] {info['timestamp']}")
        print(f"  {info['src_ip']}:{info.get('src_port', '-')} → "
              f"{info['dst_ip']}:{info.get('dst_port', '-')}")
        print(f"  Protocol: {info['protocol']} | Size: {info['length']} bytes")
    
    def start_capture(self, count=10):
        """
        Start capturing packets
        
        Args:
            count: Number of packets to capture (0 = infinite)
        """
        print(f"\n🎯 Starting capture... (capturing {count} packets)")
        print("-" * 60)
        
        try:
            # This is the main capture function from Scapy
            sniff(
                iface=self.interface,
                prn=self.packet_callback,  # Call our function for each packet
                count=count,
                store=False  # Don't store in memory (we handle it ourselves)
            )
            
            print("\n" + "=" * 60)
            print(f"✓ Capture complete! Total packets: {self.packet_count}")
            print("=" * 60)
            
        except PermissionError:
            print("\n❌ ERROR: Need administrator privileges!")
            print("   Please run VS Code as Administrator")
            sys.exit(1)
        except Exception as e:
            print(f"\n❌ ERROR: {e}")
            sys.exit(1)
    
    def get_captured_packets(self):
        """Return all captured packets"""
        return self.packets_captured
    
    def save_to_file(self, filename):
        """Save captured packets to a text file"""
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(f"Network Traffic Capture - {datetime.now()}\n")
            f.write("=" * 60 + "\n\n")
            
            for pkt in self.packets_captured:
                f.write(f"[Packet #{pkt['number']}] {pkt['timestamp']}\n")
                f.write(f"  {pkt['src_ip']}:{pkt.get('src_port', '-')} → "
                       f"{pkt['dst_ip']}:{pkt.get('dst_port', '-')}\n")
                f.write(f"  Protocol: {pkt['protocol']} | Size: {pkt['length']} bytes\n\n")
        
        print(f"✓ Packets saved to: {filename}")


# Test the monitor if this file is run directly
if __name__ == "__main__":
    print("\n🚀 Testing Traffic Monitor...\n")
    
    # Create monitor
    monitor = TrafficMonitor()
    
    # Capture 10 packets
    monitor.start_capture(count=10)
    
    # Save to file
    monitor.save_to_file("captured_traffic.txt")
    
    print("\n✅ Test complete!")