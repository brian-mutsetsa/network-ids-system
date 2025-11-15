"""
Test ML Components - Feature extraction and detection
"""

import sys
sys.path.append('.')

from capture.traffic_monitor import TrafficMonitor
from ml.feature_extractor import FeatureExtractor
from ml.detector import AnomalyDetector
from ml.classifier import AttackClassifier

def main():
    print("\n" + "="*70)
    print("   ML COMPONENTS TEST")
    print("="*70)
    
    # Step 1: Capture traffic
    print("\n[Step 1] Capturing network traffic...")
    monitor = TrafficMonitor()
    monitor.start_capture(count=50)
    packets = monitor.get_captured_packets()
    print(f"✓ Captured {len(packets)} packets")
    
    # Step 2: Extract features
    print("\n[Step 2] Extracting features...")
    extractor = FeatureExtractor()
    features = extractor.extract_features(packets)
    
    print("\n📊 Extracted Features:")
    for key, value in features.items():
        print(f"  {key}: {value:.2f}" if isinstance(value, float) else f"  {key}: {value}")
    
    # Step 3: Train detector on this "normal" traffic
    print("\n[Step 3] Training anomaly detector...")
    detector = AnomalyDetector()
    
    # Create training data (simulate normal traffic by capturing more)
    print("  Capturing training data...")
    training_features = []
    for i in range(10):
        monitor_train = TrafficMonitor()
        monitor_train.start_capture(count=20)
        train_packets = monitor_train.get_captured_packets()
        train_features = extractor.extract_features(train_packets)
        training_features.append(train_features)
        print(f"  Training batch {i+1}/10 complete")
    
    detector.train(training_features)
    
    # Step 4: Test detection
    print("\n[Step 4] Testing anomaly detection...")
    result = detector.predict(features)
    
    print("\n🔍 Detection Result:")
    print(f"  Anomaly Detected: {result['anomaly']}")
    print(f"  Confidence: {result.get('confidence', 0):.2f}")
    print(f"  Anomaly Score: {result.get('anomaly_score', 0):.4f}")
    
    # Step 5: Classify attack type
    print("\n[Step 5] Classifying attack type...")
    classifier = AttackClassifier()
    classification = classifier.classify(features, result)
    
    print("\n🎯 Classification Result:")
    print(f"  Type: {classification['type']}")
    print(f"  Confidence: {classification['confidence']:.2f}")
    print(f"  Severity: {classification['severity']}")
    print(f"  Description: {classification['description']}")
    
    print("\n💡 Recommendations:")
    for i, rec in enumerate(classification['recommendations'], 1):
        print(f"  {i}. {rec}")
    
    # Step 6: Save model
    print("\n[Step 6] Saving trained model...")
    detector.save_model('models/anomaly_detector.pkl')
    
    print("\n" + "="*70)
    print("✅ ML COMPONENTS TEST COMPLETE!")
    print("="*70 + "\n")

if __name__ == "__main__":
    main()