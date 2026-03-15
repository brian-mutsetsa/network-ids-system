"""
FastAPI Backend - REST API for the IDS System
Enhanced with continuous background monitoring and real-time alerts
"""

from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import sys
import os
from datetime import datetime
import json
import threading
import time

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from capture.traffic_monitor import TrafficMonitor
from ml.feature_extractor import FeatureExtractor
from ml.detector import AnomalyDetector
from ml.trained_classifier import TrainedMLClassifier

app = FastAPI(title="Network IDS API")

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global state
ids_state = {
    'monitoring': False,
    'monitor_thread': None,
    'stop_monitoring': False,
    'alerts': [],
    'stats': {
        'total_packets': 0,
        'total_alerts': 0,
        'last_capture': None
    }
}

# Initialize ML components
print("\n" + "="*70)
print("   INITIALIZING IDS API SERVER")
print("="*70)

extractor = FeatureExtractor()
detector = AnomalyDetector()
classifier = TrainedMLClassifier()

# Load trained anomaly detection model
print("\nLoading anomaly detection model...")
try:
    detector.load_model('models/anomaly_detector.pkl')
    print("✓ Anomaly detector loaded")
except:
    print("⚠️ Anomaly detector not loaded - will train on first use")

print("\n" + "="*70)


def extract_attack_details(packets, classification_type):
    """
    Extract detailed attack information from packets
    
    Returns dict with: source_ip, dest_ip, ports_targeted, methodology, vulnerabilities, impact
    """
    if not packets:
        return {}
    
    # Collect IPs and ports
    source_ips = set()
    dest_ips = set()
    dest_ports = set()
    src_ports = set()
    protocols = set()
    
    for pkt in packets:
        if pkt.get('src_ip'):
            source_ips.add(pkt['src_ip'])
        if pkt.get('dst_ip'):
            dest_ips.add(pkt['dst_ip'])
        if pkt.get('dst_port') and pkt['dst_port'] != '-':
            dest_ports.add(int(pkt['dst_port']))
        if pkt.get('src_port') and pkt['src_port'] != '-':
            src_ports.add(int(pkt['src_port']))
        if pkt.get('protocol'):
            protocols.add(pkt['protocol'])
    
    # Primary attacker and victim - identify by IP pattern
    all_ips = list(source_ips | dest_ips)
    primary_source = "Unknown"
    primary_dest = "Unknown"
    
    # In our network: .20 = Kali (attacker), .1 = Windows (victim)
    for ip in all_ips:
        if '.20' in ip:
            primary_source = ip
        elif '.1' in ip:
            primary_dest = ip
    
    # Fallback if pattern matching fails
    if primary_source == "Unknown" and all_ips:
        primary_source = all_ips[0]
    if primary_dest == "Unknown" and len(all_ips) > 1:
        primary_dest = [ip for ip in all_ips if ip != primary_source][0]
    elif primary_dest == "Unknown" and all_ips:
        primary_dest = all_ips[0]
    
    # Build attack methodology based on type
    methodology = get_attack_methodology(classification_type, len(dest_ports), protocols)
    
    # Identify vulnerabilities
    vulnerabilities = identify_vulnerabilities(classification_type, dest_ports)
    
    # Assess impact
    impact = assess_impact(classification_type, dest_ports)
    
    # Get affected services
    affected_services = get_affected_services(dest_ports)
    
    return {
        'source_ip': primary_source,
        'dest_ip': primary_dest,
        'source_ips': list(source_ips),
        'dest_ips': list(dest_ips),
        'ports_targeted': sorted(list(dest_ports))[:50],  # Limit to first 50
        'total_ports_scanned': len(dest_ports),
        'protocols_used': list(protocols),
        'attack_methodology': methodology,
        'vulnerabilities_exploited': vulnerabilities,
        'impact_assessment': impact,
        'affected_services': affected_services
    }


def get_attack_methodology(attack_type, port_count, protocols):
    """Generate attack methodology description"""
    
    methodologies = {
        'PortScan': f"""
**Reconnaissance Phase - Network Enumeration**

1. **Initial Contact**: Attacker initiated connection attempts to {port_count} different ports
2. **Scanning Technique**: SYN scan method used to avoid full TCP handshake detection
3. **Target Probing**: Systematic enumeration of services to identify open ports and running services
4. **Information Gathering**: Collecting data on network topology, active services, and potential entry points
5. **Next Phase Preparation**: Scan results will be used to plan targeted exploitation attempts

**Attack Progression**: This is typically the first stage of a multi-phase attack.
        """.strip(),
        
        'UDP-Flood': f"""
**Denial of Service - UDP Amplification Attack**

1. **Traffic Generation**: Attacker sent high-volume UDP packets to overwhelm target resources
2. **Protocol Exploitation**: Leveraged connectionless nature of UDP (no handshake required)
3. **Resource Exhaustion**: Flooded network bandwidth and processing capacity
4. **Service Disruption**: Legitimate traffic unable to reach destination due to congestion
5. **Amplification**: May be using vulnerable UDP services (DNS, NTP) for traffic amplification

**Attack Goal**: Render target system or network unavailable to legitimate users.
        """.strip(),
        
        'DDoS': f"""
**Distributed Denial of Service - Coordinated Attack**

1. **Botnet Deployment**: Multiple compromised systems attacking simultaneously
2. **Traffic Flood**: Overwhelming packet rate ({'>1000 packets/second'}) exceeds capacity
3. **Multi-Protocol**: Using {', '.join(protocols)} protocols to bypass single-vector defenses
4. **Persistence**: Sustained attack designed to exhaust all defensive resources
5. **Service Collapse**: Target system unable to process legitimate requests

**Attack Scale**: Extremely high severity - indicates organized, resourced attack campaign.
        """.strip(),
        
        'DoS Hulk': f"""
**Denial of Service - Application Layer Attack**

1. **HTTP Flood**: Sending seemingly legitimate HTTP requests at high rate
2. **Resource Depletion**: Exhausting web server threads, CPU, and memory
3. **Obfuscation**: Randomized user agents and referrers to evade simple filters
4. **Persistence**: Maintaining constant pressure to prevent service recovery
5. **Target Focus**: Specifically attacking web application layer (Layer 7)

**Attack Method**: Hulk tool generates unique requests to bypass caching and rate limits.
        """.strip(),
        
        'SSH-Patator': f"""
**Credential Attack - SSH Brute Force**

1. **Service Discovery**: Identified SSH service running on port 22
2. **Dictionary Attack**: Attempting common username/password combinations
3. **Automated Tool**: Using Patator or similar brute-force framework
4. **Rate Control**: Throttled attempts to avoid account lockouts
5. **Persistence**: Systematically testing thousands of credentials

**Attack Goal**: Gain unauthorized shell access to compromise the system.
        """.strip(),
        
        'FTP-Patator': f"""
**Credential Attack - FTP Brute Force**

1. **Service Discovery**: Identified FTP service on port 21
2. **Dictionary Attack**: Testing common FTP credentials
3. **Anonymous Probing**: Likely tested anonymous login first
4. **Credential Enumeration**: Systematic username and password testing
5. **Access Attempt**: Trying to gain file system access

**Attack Goal**: Compromise FTP server to upload malicious files or steal data.
        """.strip()
    }
    
    return methodologies.get(attack_type, f"Attack executed using {', '.join(protocols)} protocol(s) targeting {port_count} ports.")


def identify_vulnerabilities(attack_type, ports):
    """Identify which vulnerabilities are being exploited"""
    
    vulnerabilities = []
    
    # Port-specific vulnerabilities
    port_vulns = {
        21: "FTP service exposed - plaintext credentials, anonymous access risk",
        22: "SSH service accessible - susceptible to brute-force if weak passwords used",
        23: "Telnet service (unencrypted) - credentials sent in plaintext",
        25: "SMTP service exposed - potential email relay abuse",
        53: "DNS service accessible - amplification attack vector",
        80: "HTTP service exposed - web application vulnerabilities",
        110: "POP3 service exposed - email credential theft risk",
        135: "Windows RPC exposed - remote code execution vulnerabilities",
        139: "NetBIOS service exposed - Windows network enumeration",
        143: "IMAP service exposed - email account compromise risk",
        443: "HTTPS service exposed - SSL/TLS vulnerabilities possible",
        445: "SMB service exposed - EternalBlue, ransomware, lateral movement",
        3306: "MySQL database exposed - SQL injection, data breach risk",
        3389: "RDP service exposed - brute-force, BlueKeep vulnerability",
        5432: "PostgreSQL exposed - database compromise risk",
        8080: "Alternative HTTP port - often less secured than port 80"
    }
    
    for port in ports:
        if port in port_vulns:
            vulnerabilities.append(f"Port {port}: {port_vulns[port]}")
    
    # Attack-type specific vulnerabilities
    if attack_type == 'PortScan':
        vulnerabilities.append("Insufficient network segmentation - too many services visible")
        vulnerabilities.append("Missing intrusion detection/prevention system")
        vulnerabilities.append("No rate limiting on connection attempts")
    
    elif attack_type in ['UDP-Flood', 'DDoS', 'DoS Hulk']:
        vulnerabilities.append("Inadequate DDoS protection - no traffic filtering")
        vulnerabilities.append("Insufficient bandwidth capacity for attack absorption")
        vulnerabilities.append("Missing rate limiting on inbound connections")
        vulnerabilities.append("No upstream ISP-level DDoS mitigation")
    
    elif attack_type in ['SSH-Patator', 'FTP-Patator']:
        vulnerabilities.append("Weak password policy - vulnerable to dictionary attacks")
        vulnerabilities.append("No account lockout after failed login attempts")
        vulnerabilities.append("Missing fail2ban or similar brute-force protection")
        vulnerabilities.append("No multi-factor authentication (MFA) implemented")
    
    if not vulnerabilities:
        vulnerabilities.append("General network exposure - services accessible from external sources")
    
    return vulnerabilities


def assess_impact(attack_type, ports):
    """Assess the potential impact of the attack"""
    
    impacts = {
        'PortScan': {
            'severity': 'High',
            'immediate': 'Information disclosure - attacker now knows which services are running',
            'potential': [
                'Blueprint for targeted attacks on discovered services',
                'Identification of vulnerable software versions',
                'Network topology mapping completed',
                'Preparation for exploitation phase'
            ],
            'business': 'Precursor to data breach, system compromise, or ransomware attack'
        },
        
        'UDP-Flood': {
            'severity': 'High',
            'immediate': 'Service degradation or complete unavailability',
            'potential': [
                'Network congestion affecting all services',
                'Legitimate users unable to access systems',
                'Revenue loss from downtime',
                'Bandwidth exhaustion'
            ],
            'business': 'Business disruption, customer dissatisfaction, potential SLA violations'
        },
        
        'DDoS': {
            'severity': 'Critical',
            'immediate': 'Complete service outage - systems unreachable',
            'potential': [
                'Extended downtime (hours to days if not mitigated)',
                'Massive financial losses from service unavailability',
                'Reputation damage from service disruption',
                'Potential smokescreen for simultaneous data breach'
            ],
            'business': 'Severe revenue impact, customer loss, brand damage, regulatory penalties'
        },
        
        'DoS Hulk': {
            'severity': 'High',
            'immediate': 'Web application unresponsive or extremely slow',
            'potential': [
                'E-commerce transactions failing',
                'Customer-facing services down',
                'Internal web applications inaccessible',
                'Server resource exhaustion'
            ],
            'business': 'Direct revenue loss, customer frustration, competitive disadvantage'
        },
        
        'SSH-Patator': {
            'severity': 'Critical',
            'immediate': 'Unauthorized access attempts to system shell',
            'potential': [
                'Complete system compromise if successful',
                'Data theft and exfiltration',
                'Malware installation and persistence',
                'Lateral movement to other systems',
                'Ransomware deployment'
            ],
            'business': 'Data breach, regulatory fines (GDPR, HIPAA), ransomware payment demands, total system rebuild costs'
        },
        
        'FTP-Patator': {
            'severity': 'High',
            'immediate': 'Unauthorized file system access attempts',
            'potential': [
                'Sensitive file theft',
                'Malicious file uploads (malware, backdoors)',
                'Website defacement',
                'Data manipulation or destruction'
            ],
            'business': 'Data breach, intellectual property theft, compliance violations'
        }
    }
    
    impact_data = impacts.get(attack_type, {
        'severity': 'Medium',
        'immediate': 'Suspicious network activity detected',
        'potential': ['System compromise risk', 'Data breach possibility'],
        'business': 'Potential security incident requiring investigation'
    })
    
    # Add port-specific impact
    critical_ports = {445, 3389, 22, 21}
    if any(p in ports for p in critical_ports):
        impact_data['critical_exposure'] = f"Critical services exposed on ports: {', '.join(map(str, critical_ports & set(ports)))}"
    
    return impact_data


def get_affected_services(ports):
    """Map ports to service names"""
    
    service_map = {
        20: "FTP Data Transfer",
        21: "FTP Control",
        22: "SSH (Secure Shell)",
        23: "Telnet",
        25: "SMTP (Email)",
        53: "DNS",
        67: "DHCP Server",
        68: "DHCP Client",
        69: "TFTP",
        80: "HTTP (Web)",
        110: "POP3 (Email)",
        119: "NNTP (News)",
        123: "NTP (Time)",
        135: "Windows RPC",
        137: "NetBIOS Name Service",
        138: "NetBIOS Datagram",
        139: "NetBIOS Session (SMB)",
        143: "IMAP (Email)",
        161: "SNMP",
        162: "SNMP Trap",
        389: "LDAP",
        443: "HTTPS (Secure Web)",
        445: "SMB (Windows File Sharing)",
        465: "SMTPS (Secure Email)",
        514: "Syslog",
        587: "SMTP Submission",
        636: "LDAPS (Secure LDAP)",
        993: "IMAPS (Secure IMAP)",
        995: "POP3S (Secure POP3)",
        1433: "Microsoft SQL Server",
        1521: "Oracle Database",
        3306: "MySQL Database",
        3389: "RDP (Remote Desktop)",
        5432: "PostgreSQL Database",
        5900: "VNC (Remote Desktop)",
        8080: "HTTP Alternate",
        8443: "HTTPS Alternate"
    }
    
    services = []
    for port in sorted(ports):
        service_name = service_map.get(port, f"Unknown Service (Port {port})")
        services.append({'port': port, 'service': service_name})
    
    return services[:20]  # Limit to first 20 services


# ===== API ENDPOINTS =====

@app.get("/")
async def root():
    return {
        "status": "IDS System API Running",
        "version": "2.0",
        "ml_classifier": "CIC-IDS2017 Trained Model",
        "accuracy": "99.86%"
    }

@app.get("/api/status")
async def get_status():
    """Get system status"""
    return {
        'monitoring': ids_state['monitoring'],
        'model_loaded': detector.is_trained,
        'ml_classifier_loaded': classifier.is_loaded,
        'stats': ids_state['stats']
    }

@app.get("/api/alerts")
async def get_alerts(limit: int = 50):
    """Get recent alerts"""
    return {
        'alerts': ids_state['alerts'][-limit:],
        'total': len(ids_state['alerts'])
    }

@app.get("/api/stats")
async def get_stats():
    """Get dashboard statistics"""

    # Calculate severity breakdown
    severity_count = {'low': 0, 'medium': 0, 'high': 0, 'critical': 0}
    for alert in ids_state['alerts']:
        severity = alert.get('severity', 'medium')
        severity_count[severity] = severity_count.get(severity, 0) + 1

    # Calculate attack types
    attack_types = {}
    for alert in ids_state['alerts']:
        attack_type = alert.get('type', 'Unknown')
        attack_types[attack_type] = attack_types.get(attack_type, 0) + 1

    return {
        'total_packets': ids_state['stats']['total_packets'],
        'total_alerts': ids_state['stats']['total_alerts'],
        'active_threats': sum(1 for a in ids_state['alerts'] if a.get('severity') in ['high', 'critical']),
        'severity_breakdown': severity_count,
        'attack_types': attack_types,
        'last_capture': ids_state['stats']['last_capture'],
        'ml_accuracy': '99.86%' if classifier.is_loaded else 'N/A'
    }


def continuous_monitoring_loop():
    """Background thread function for continuous traffic monitoring"""
    print("\n" + "="*70)
    print("🔴 CONTINUOUS MONITORING STARTED")
    print("="*70)
    
    from config.settings import NETWORK_INTERFACE
    capture_count = 0
    
    while ids_state['monitoring'] and not ids_state['stop_monitoring']:
        try:
            capture_count += 1
            print(f"\n[Capture #{capture_count}] {datetime.now().strftime('%H:%M:%S')} - Starting continuous capture...")
            
            # Capture traffic for 3 seconds or until 50 packets collected
            monitor = TrafficMonitor(interface=NETWORK_INTERFACE)
            monitor.start_capture(count=50, timeout=3)
            packets = monitor.get_captured_packets()
            
            if len(packets) > 0:
                print(f"  ✓ Captured {len(packets)} packets")
                
                # Update stats
                ids_state['stats']['total_packets'] += len(packets)
                ids_state['stats']['last_capture'] = datetime.now().isoformat()
                
                # Analyze with ML
                features = extractor.extract_features(packets)
                detection = detector.predict(features)
                classification = classifier.classify(features, detection, packets)
                
                # Create alert if attack detected
                if classification['type'] != 'BENIGN':
                    attack_details = extract_attack_details(packets, classification['type'])
                    
                    alert = {
                        'id': len(ids_state['alerts']) + 1,
                        'timestamp': datetime.now().isoformat(),
                        'type': classification['type'],
                        'severity': classification['severity'],
                        'confidence': float(classification['confidence']),
                        'description': classification['description'],
                        'recommendations': classification['recommendations'],
                        'ml_powered': classification.get('ml_powered', True),
                        
                        # Forensic details
                        'source_ip': attack_details.get('source_ip'),
                        'dest_ip': attack_details.get('dest_ip'),
                        'source_ips': attack_details.get('source_ips', []),
                        'dest_ips': attack_details.get('dest_ips', []),
                        'ports_targeted': attack_details.get('ports_targeted', []),
                        'total_ports_scanned': attack_details.get('total_ports_scanned', 0),
                        'protocols_used': attack_details.get('protocols_used', []),
                        'attack_methodology': attack_details.get('attack_methodology', ''),
                        'vulnerabilities_exploited': attack_details.get('vulnerabilities_exploited', []),
                        'impact_assessment': attack_details.get('impact_assessment', {}),
                        'affected_services': attack_details.get('affected_services', []),
                        
                        'features': {
                            'packet_count': int(features['packet_count']),
                            'bytes_per_second': float(features['bytes_per_second']),
                        }
                    }
                    
                    ids_state['alerts'].append(alert)
                    ids_state['stats']['total_alerts'] += 1
                    print(f"  🚨 {classification['type']} ALERT detected! (Confidence: {classification['confidence']:.0%})")
                else:
                    print(f"  ✓ Normal traffic detected ({len(packets)} packets)")
            else:
                print(f"  - No packets captured (idle network)")
            
            # Brief pause between captures to avoid CPU spinning
            time.sleep(0.5)
            
        except KeyboardInterrupt:
            print("\n⚠️ Monitoring interrupted by user")
            break
        except Exception as e:
            print(f"  ✗ Error in monitoring loop: {e}")
            import traceback
            traceback.print_exc()
            time.sleep(1)
    
    ids_state['monitoring'] = False
    ids_state['stop_monitoring'] = False
    print("\n" + "="*70)
    print("🟢 CONTINUOUS MONITORING STOPPED")
    print(f"   Total captures: {capture_count}")
    print(f"   Total alerts: {ids_state['stats']['total_alerts']}")
    print("="*70)


@app.post("/api/monitoring/start")
async def start_monitoring():
    """Start continuous background traffic monitoring"""
    if ids_state['monitoring']:
        return {'success': False, 'message': 'Monitoring already running'}
    
    # Start monitoring in background thread
    ids_state['monitoring'] = True
    ids_state['stop_monitoring'] = False
    ids_state['alerts'] = []  # Clear old alerts
    
    monitor_thread = threading.Thread(target=continuous_monitoring_loop, daemon=True)
    ids_state['monitor_thread'] = monitor_thread
    monitor_thread.start()
    
    print("✓ Monitoring started") 
    return {
        'success': True,
        'message': 'Continuous monitoring started',
        'monitoring': True
    }


@app.post("/api/monitoring/stop")
async def stop_monitoring():
    """Stop continuous background traffic monitoring"""
    if not ids_state['monitoring']:
        return {'success': False, 'message': 'Monitoring not running'}
    
    # Signal the monitoring thread to stop
    ids_state['stop_monitoring'] = True
    
    # Wait for thread to finish (max 5 seconds)
    if ids_state['monitor_thread']:
        ids_state['monitor_thread'].join(timeout=5)
    
    ids_state['monitoring'] = False
    
    print("✓ Monitoring stopped")
    return {
        'success': True,
        'message': 'Continuous monitoring stopped',
        'monitoring': False,
        'total_alerts': ids_state['stats']['total_alerts']
    }


@app.post("/api/capture")
async def capture_traffic(packet_count: int = 30, timeout: int = 5):
    """
    Manually capture and analyze traffic - FAST with timeout
    
    Args:
        packet_count: Target packets to capture (will return earlier if timeout reached)
        timeout: Maximum seconds to wait for packets (default 5 seconds)
    """

    try:
        # Capture packets with timeout - will return whichever comes first:
        # - 30 packets collected, OR
        # - 5 seconds elapsed
        from config.settings import NETWORK_INTERFACE
        monitor = TrafficMonitor(interface=NETWORK_INTERFACE)
        monitor.start_capture(count=packet_count, timeout=timeout)
        packets = monitor.get_captured_packets()

        if len(packets) == 0:
            return {'success': False, 'message': 'No packets captured'}

        # Update stats
        ids_state['stats']['total_packets'] += len(packets)
        ids_state['stats']['last_capture'] = datetime.now().isoformat()

        # Analyze with ML
        features = extractor.extract_features(packets)
        detection = detector.predict(features)
        classification = classifier.classify(features, detection, packets)

        # Create alert if anomaly or if ML detected attack
        is_attack = classification['type'] != 'BENIGN'

        if is_attack:
            # Extract detailed attack information
            attack_details = extract_attack_details(packets, classification['type'])
            
            alert = {
                'id': len(ids_state['alerts']) + 1,
                'timestamp': datetime.now().isoformat(),
                'type': classification['type'],
                'severity': classification['severity'],
                'confidence': float(classification['confidence']),
                'description': classification['description'],
                'recommendations': classification['recommendations'],
                'ml_powered': classification.get('ml_powered', True),
                
                # NEW: Forensic details
                'source_ip': attack_details.get('source_ip'),
                'dest_ip': attack_details.get('dest_ip'),
                'source_ips': attack_details.get('source_ips', []),
                'dest_ips': attack_details.get('dest_ips', []),
                'ports_targeted': attack_details.get('ports_targeted', []),
                'total_ports_scanned': attack_details.get('total_ports_scanned', 0),
                'protocols_used': attack_details.get('protocols_used', []),
                'attack_methodology': attack_details.get('attack_methodology', ''),
                'vulnerabilities_exploited': attack_details.get('vulnerabilities_exploited', []),
                'impact_assessment': attack_details.get('impact_assessment', {}),
                'affected_services': attack_details.get('affected_services', []),
                
                # Original features
                'features': {
                    'packet_count': int(features['packet_count']),
                    'bytes_per_second': float(features['bytes_per_second']),
                    'unique_src_ips': int(features['unique_src_ips']),
                    'unique_dst_ips': int(features['unique_dst_ips'])
                }
            }
            ids_state['alerts'].append(alert)
            ids_state['stats']['total_alerts'] += 1

        return {
            'success': True,
            'packets_captured': len(packets),
            'attack_detected': is_attack,
            'classification': {
                'type': classification['type'],
                'severity': classification['severity'],
                'confidence': float(classification['confidence']),
                'description': classification['description'],
                'ml_powered': classification.get('ml_powered', True),
                'accuracy': '99.86%' if classification.get('ml_powered') else 'Rule-based'
            }
        }

    except Exception as e:
        import traceback
        traceback.print_exc()
        return {'success': False, 'message': str(e)}

@app.post("/api/start-monitoring")
async def start_monitoring(background_tasks: BackgroundTasks):
    """Start continuous monitoring"""
    if ids_state['monitoring']:
        return {'success': False, 'message': 'Already monitoring'}

    ids_state['monitoring'] = True
    return {'success': True, 'message': 'Monitoring started'}

@app.post("/api/stop-monitoring")
async def stop_monitoring():
    """Stop continuous monitoring"""
    ids_state['monitoring'] = False
    return {'success': True, 'message': 'Monitoring stopped'}

@app.delete("/api/alerts/clear")
async def clear_alerts():
    """Clear all alerts"""
    ids_state['alerts'] = []
    ids_state['stats']['total_alerts'] = 0
    return {'success': True, 'message': 'Alerts cleared'}

@app.get("/api/alert/{alert_id}")
async def get_alert_detail(alert_id: int):
    """Get detailed information about a specific alert"""
    for alert in ids_state['alerts']:
        if alert['id'] == alert_id:
            return alert
    return {'error': 'Alert not found'}

@app.get("/api/model-info")
async def get_model_info():
    """Get information about the ML model"""
    if classifier.is_loaded:
        return {
            'loaded': True,
            'accuracy': '99.86%',
            'attack_types': classifier.model_data.get('classes', []),
            'training_samples': '1.7 million',
            'dataset': 'CIC-IDS2017',
            'algorithm': 'Random Forest (100 trees)',
            'features': len(classifier.feature_names)
        }
    else:
        return {
            'loaded': False,
            'message': 'ML model not loaded'
        }

from analysis.breach_analyzer import BreachAnalyzer

# Initialize breach analyzer
breach_analyzer = BreachAnalyzer()

@app.get("/api/breach-analysis/{alert_id}")
async def get_breach_analysis(alert_id: int):
    """Get detailed breach analysis for a specific alert"""
    try:
        alert = None
        for a in ids_state["alerts"]:
            if a["id"] == alert_id:
                alert = a
                break

        if not alert:
            return {"error": "Alert not found"}

        analysis = breach_analyzer.analyze_breach(alert)
        return analysis

    except Exception as e:
        return {"error": str(e)}

@app.post("/api/test-alert")
async def create_test_alert():
    """Create a test alert for demonstration"""
    test_alert = {
        'id': len(ids_state['alerts']) + 1,
        'timestamp': datetime.now().isoformat(),
        'type': 'PortScan',
        'severity': 'high',
        'confidence': 0.92,
        'description': 'Suspicious port scanning activity detected',
        'recommendations': [
            'Block source IP addresses immediately',
            'Review firewall rules for exposed ports',
            'Enable intrusion prevention system',
            'Monitor for follow-up attacks'
        ],
        'ml_powered': True,
        
        # Forensic details
        'source_ip': '192.168.56.20',
        'dest_ip': '192.168.56.1',
        'source_ips': ['192.168.56.20'],
        'dest_ips': ['192.168.56.1'],
        'ports_targeted': [22, 80, 135, 139, 443, 445, 3389],
        'total_ports_scanned': 100,
        'protocols_used': ['TCP'],
        'attack_methodology': 'Systematic port enumeration using SYN scanning technique',
        'vulnerabilities_exploited': [
            'Port 22: SSH service exposed',
            'Port 445: SMB service exposed - EternalBlue risk',
            'Port 3389: RDP service exposed - brute-force risk'
        ],
        'impact_assessment': {
            'severity': 'High',
            'immediate': 'Network reconnaissance completed',
            'potential': ['Targeted exploitation', 'Data breach', 'Ransomware'],
            'business': 'Precursor to major security incident'
        },
        'affected_services': [
            {'port': 22, 'service': 'SSH'},
            {'port': 80, 'service': 'HTTP'},
            {'port': 443, 'service': 'HTTPS'},
            {'port': 445, 'service': 'SMB'},
            {'port': 3389, 'service': 'RDP'}
        ],
        
        'features': {
            'packet_count': 450,
            'bytes_per_second': 15234,
            'unique_src_ips': 1,
            'unique_dst_ips': 1
        }
    }
    ids_state['alerts'].append(test_alert)
    ids_state['stats']['total_alerts'] += 1
    return {'success': True, 'alert': test_alert}

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*70)
    print("   STARTING IDS API SERVER WITH ENHANCED FORENSICS")
    print("="*70)
    print("\n✓ API will be available at: http://localhost:8000")
    print("✓ API docs at: http://localhost:8000/docs")
    print("✓ ML Classifier: 99.86% accuracy (CIC-IDS2017 trained)")
    print("✓ Enhanced breach analysis with forensic details")
    print("\nPress Ctrl+C to stop\n")

    uvicorn.run(app, host="0.0.0.0", port=8000)





