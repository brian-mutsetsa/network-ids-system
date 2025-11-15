"""
Main IDS System - Real-time monitoring and detection
"""

import sys
sys.path.append('.')

from capture.traffic_monitor import TrafficMonitor
from ml.feature_extractor import FeatureExtractor
from ml.detector import AnomalyDetector
from ml.classifier import AttackClassifier
from datetime import datetime
import time

class IDSSystem:
    """Real-time Intrusion Detection System"""
    
    def __init__(self, model_path='models/anomaly_detector.pkl'):
        print("\n" + "="*70)
        print("   NETWORK INTRUSION DETECTION SYSTEM")
        print("="*70)
        
        # Initialize components
        print("\n[Initializing Components]")
        self.monitor = TrafficMonitor()
        self.extractor = FeatureExtractor()
        self.detector = AnomalyDetector()
        self.classifier = AttackClassifier()
        
        # Load trained model
        print(f"Loading model from {model_path}...")
        if self.detector.load_model(model_path):
            print("✓ Model loaded successfully")
        else:
            print("⚠️ Warning: Model not loaded. Train first using test_ml.py")
        
        self.alerts = []
        self.packet_buffer = []
        self.window_size = 50  # Analyze every 50 packets
        
    def start_monitoring(self, duration_seconds=60):
        """
        Start continuous monitoring
        
        Args:
            duration_seconds: How long to monitor (0 = infinite)
        """
        print(f"\n[Starting Monitoring]")
        print(f"Duration: {duration_seconds} seconds" if duration_seconds > 0 else "Duration: Continuous")
        print(f"Window Size: {self.window_size} packets")
        print(f"Press Ctrl+C to stop\n")
        print("="*70)
        
        start_time = time.time()
        packet_count = 0
        
        try:
            while True:
                # Check if duration expired
                if duration_seconds > 0 and (time.time() - start_time) > duration_seconds:
                    break
                
                # Capture packets in batches
                print(f"\n[{datetime.now().strftime('%H:%M:%S')}] Capturing packets...")
                monitor = TrafficMonitor()
                monitor.start_capture(count=self.window_size)
                packets = monitor.get_captured_packets()
                
                if len(packets) == 0:
                    print("⚠️ No packets captured. Waiting...")
                    time.sleep(1)
                    continue
                
                packet_count += len(packets)
                print(f"✓ Captured {len(packets)} packets (Total: {packet_count})")
                
                # Analyze the traffic
                self._analyze_traffic(packets)
                
                # Small delay before next capture
                time.sleep(2)
                
        except KeyboardInterrupt:
            print("\n\n[Monitoring Stopped by User]")
        
        self._print_summary()
    
    def _analyze_traffic(self, packets):
        """Analyze captured packets for threats"""
        
        # Extract features
        features = self.extractor.extract_features(packets)
        
        # Detect anomaly
        detection = self.detector.predict(features)
        
        # Classify if anomaly detected
        classification = self.classifier.classify(features, detection)
        
        # Print results
        print(f"\n📊 Analysis Results:")
        print(f"  Packets: {features['packet_count']}")
        print(f"  Protocols: TCP={features['tcp_ratio']:.0%} UDP={features['udp_ratio']:.0%}")
        print(f"  Traffic: {features['bytes_per_second']:.0f} bytes/sec")
        
        if detection['anomaly']:
            self._handle_alert(detection, classification, features)
        else:
            print(f"  Status: ✓ Normal (Confidence: {detection['confidence']:.2f})")
    
    def _handle_alert(self, detection, classification, features):
        """Handle detected threat"""
        
        alert = {
            'timestamp': datetime.now().isoformat(),
            'type': classification['type'],
            'severity': classification['severity'],
            'confidence': classification['confidence'],
            'anomaly_score': detection['anomaly_score'],
            'features': features
        }
        
        self.alerts.append(alert)
        
        # Print alert
        print(f"\n{'='*70}")
        print(f"🚨 ALERT #{len(self.alerts)} - {classification['severity'].upper()} SEVERITY")
        print(f"{'='*70}")
        print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Type: {classification['type']}")
        print(f"Confidence: {classification['confidence']:.2%}")
        print(f"Description: {classification['description']}")
        print(f"\n💡 Immediate Actions:")
        for i, rec in enumerate(classification['recommendations'][:3], 1):
            print(f"  {i}. {rec}")
        print(f"{'='*70}\n")
        
        # Save alert to file
        self._save_alert(alert)
    
    def _save_alert(self, alert):
        """Save alert to file"""
        filename = f"data/alerts_{datetime.now().strftime('%Y%m%d')}.txt"
        
        with open(filename, 'a', encoding='utf-8') as f:
            f.write(f"\n{'='*70}\n")
            f.write(f"ALERT - {alert['timestamp']}\n")
            f.write(f"{'='*70}\n")
            f.write(f"Type: {alert['type']}\n")
            f.write(f"Severity: {alert['severity']}\n")
            f.write(f"Confidence: {alert['confidence']:.2%}\n")
            f.write(f"Anomaly Score: {alert['anomaly_score']:.4f}\n")
            f.write(f"\nKey Metrics:\n")
            f.write(f"  Packets: {alert['features']['packet_count']}\n")
            f.write(f"  Bytes/sec: {alert['features']['bytes_per_second']:.0f}\n")
            f.write(f"  Unique IPs: {alert['features']['unique_src_ips']}\n")
            f.write(f"\n")
    
    def _print_summary(self):
        """Print monitoring summary"""
        print("\n" + "="*70)
        print("   MONITORING SUMMARY")
        print("="*70)
        print(f"Total Alerts: {len(self.alerts)}")
        
        if self.alerts:
            print("\nAlert Breakdown:")
            severity_count = {}
            type_count = {}
            
            for alert in self.alerts:
                severity = alert['severity']
                alert_type = alert['type']
                severity_count[severity] = severity_count.get(severity, 0) + 1
                type_count[alert_type] = type_count.get(alert_type, 0) + 1
            
            print("\nBy Severity:")
            for severity, count in severity_count.items():
                print(f"  {severity}: {count}")
            
            print("\nBy Type:")
            for alert_type, count in type_count.items():
                print(f"  {alert_type}: {count}")
        
        print("\n✓ Alerts saved to: data/alerts_*.txt")
        print("="*70 + "\n")


def main():
    # Create IDS system
    ids = IDSSystem()
    
    # Start monitoring for 60 seconds (change to 0 for infinite)
    ids.start_monitoring(duration_seconds=60)

if __name__ == "__main__":
    main()