"""
FastAPI Backend - REST API for the IDS System
"""

from fastapi import FastAPI, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import sys
import os
from datetime import datetime
import json

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from capture.traffic_monitor import TrafficMonitor
from ml.feature_extractor import FeatureExtractor
from ml.detector import AnomalyDetector
from ml.classifier import AttackClassifier

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
    'alerts': [],
    'stats': {
        'total_packets': 0,
        'total_alerts': 0,
        'last_capture': None
    }
}

# Initialize ML components
extractor = FeatureExtractor()
detector = AnomalyDetector()
classifier = AttackClassifier()

# Load trained model
try:
    detector.load_model('models/anomaly_detector.pkl')
    print("✓ Model loaded")
except:
    print("⚠️ Model not loaded")

# ===== API ENDPOINTS =====

@app.get("/")
async def root():
    return {"status": "IDS System API Running", "version": "1.0"}

@app.get("/api/status")
async def get_status():
    """Get system status"""
    return {
        'monitoring': ids_state['monitoring'],
        'model_loaded': detector.is_trained,
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
        'last_capture': ids_state['stats']['last_capture']
    }

@app.post("/api/capture")
async def capture_traffic(packet_count: int = 50):
    """Manually capture and analyze traffic"""
    
    try:
        # Capture packets
        monitor = TrafficMonitor()
        monitor.start_capture(count=packet_count)
        packets = monitor.get_captured_packets()
        
        if len(packets) == 0:
            return {'success': False, 'message': 'No packets captured'}
        
        # Update stats
        ids_state['stats']['total_packets'] += len(packets)
        ids_state['stats']['last_capture'] = datetime.now().isoformat()
        
        # Analyze
        features = extractor.extract_features(packets)
        detection = detector.predict(features)
        classification = classifier.classify(features, detection)
        
        # Create alert if anomaly (convert numpy bool to Python bool)
        is_anomaly = bool(detection.get('anomaly', False))
        
        if is_anomaly:
            alert = {
                'id': len(ids_state['alerts']) + 1,
                'timestamp': datetime.now().isoformat(),
                'type': classification['type'],
                'severity': classification['severity'],
                'confidence': float(classification['confidence']),
                'description': classification['description'],
                'recommendations': classification['recommendations'],
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
            'anomaly_detected': is_anomaly,
            'classification': {
                'type': classification['type'],
                'severity': classification['severity'],
                'confidence': float(classification['confidence']),
                'description': classification['description']
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

if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*70)
    print("   STARTING IDS API SERVER")
    print("="*70)
    print("\n✓ API will be available at: http://localhost:8000")
    print("✓ API docs at: http://localhost:8000/docs")
    print("\nPress Ctrl+C to stop\n")
    
    uvicorn.run(app, host="0.0.0.0", port=8000)