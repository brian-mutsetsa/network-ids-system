"""
Anomaly Detector - ML model to detect unusual traffic
"""

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import numpy as np
from pathlib import Path

class AnomalyDetector:
    """Detect anomalous network traffic using ML"""
    
    def __init__(self, contamination=0.1):
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_estimators=100,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []
        
    def train(self, training_features):
        """
        Train on normal traffic
        
        Args:
            training_features: List of feature dictionaries
        """
        print(f"Training with {len(training_features)} samples...")
        
        X, self.feature_names = self._prepare_features(training_features)
        
        if len(X) < 10:
            print("⚠️ Need at least 10 samples for training")
            return False
        
        # Scale and train
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True
        
        print("✓ Training complete!")
        return True
    
    def predict(self, features):
        """
        Detect if features are anomalous
        
        Returns:
            Dictionary with detection results
        """
        if not self.is_trained:
            return {
                'anomaly': False,
                'confidence': 0.0,
                'anomaly_score': 0.0,
                'error': 'Model not trained'
            }
        
        try:
            X, _ = self._prepare_features([features], self.feature_names)
            X_scaled = self.scaler.transform(X)
            
            prediction = self.model.predict(X_scaled)[0]
            score = self.model.score_samples(X_scaled)[0]
            
            is_anomaly = prediction == -1
            confidence = min(abs(score), 1.0)
            
            return {
                'anomaly': is_anomaly,
                'confidence': float(confidence),
                'anomaly_score': float(score)
            }
        except Exception as e:
            return {
                'anomaly': False,
                'confidence': 0.0,
                'error': str(e)
            }
    
    def _prepare_features(self, features_list, feature_names=None):
        """Convert feature dicts to numpy array"""
        if not features_list:
            return np.array([]), []
        
        if feature_names is None:
            feature_names = sorted(features_list[0].keys())
        
        X = np.array([
            [float(sample.get(feature, 0)) for feature in feature_names]
            for sample in features_list
        ])
        
        X = np.nan_to_num(X, nan=0.0, posinf=999999, neginf=-999999)
        
        return X, feature_names
    
    def save_model(self, path):
        """Save trained model"""
        if not self.is_trained:
            print("⚠️ Cannot save untrained model")
            return False
        
        try:
            Path(path).parent.mkdir(parents=True, exist_ok=True)
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_names,
                'is_trained': self.is_trained
            }
            joblib.dump(model_data, path)
            print(f"✓ Model saved to {path}")
            return True
        except Exception as e:
            print(f"❌ Error saving: {e}")
            return False
    
    def load_model(self, path):
        """Load trained model"""
        try:
            model_data = joblib.load(path)
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.feature_names = model_data['feature_names']
            self.is_trained = model_data['is_trained']
            print(f"✓ Model loaded from {path}")
            return True
        except Exception as e:
            print(f"❌ Error loading: {e}")
            return False