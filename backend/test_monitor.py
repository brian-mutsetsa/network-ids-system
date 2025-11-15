"""
Test script for the Traffic Monitor
Run this to test if packet capture is working
"""

import sys
sys.path.append('.')  # Add current directory to Python path

from capture.traffic_monitor import TrafficMonitor

def main():
    print("\n" + "="*70)
    print("   NETWORK TRAFFIC MONITOR - TEST")
    print("="*70)
    
    # Create the monitor
    monitor = TrafficMonitor()
    
    print("\n📋 Instructions:")
    print("   1. Open a web browser")
    print("   2. Visit any website (e.g., google.com)")
    print("   3. Watch the packets appear below!")
    print("\n⏳ Capturing 20 packets... (this may take a few seconds)\n")
    
    # Capture 20 packets
    monitor.start_capture(count=20)
    
    # Display summary
    packets = monitor.get_captured_packets()
    
    print("\n" + "="*70)
    print("📊 CAPTURE SUMMARY")
    print("="*70)
    
    # Count protocols
    protocol_count = {}
    for pkt in packets:
        protocol = pkt['protocol']
        protocol_count[protocol] = protocol_count.get(protocol, 0) + 1
    
    print(f"\nTotal Packets Captured: {len(packets)}")
    print("\nProtocol Breakdown:")
    for protocol, count in protocol_count.items():
        print(f"  {protocol}: {count} packets")
    
    # Save to file
    filename = "data/test_capture.txt"
    monitor.save_to_file(filename)
    
    print("\n✅ Test completed successfully!")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()
