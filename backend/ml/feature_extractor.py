"""
Feature Extractor - Converts packets into ML features
"""

import pandas as pd
from datetime import datetime

class FeatureExtractor:
    """Extract numerical features from network packets for ML"""
    
    def extract_features(self, packets_window):
        """
        Convert a list of packets into ML features
        
        Args:
            packets_window: List of packet dictionaries
            
        Returns:
            Dictionary of features
        """
        if not packets_window:
            return self._get_empty_features()
        
        df = pd.DataFrame(packets_window)
        
        features = {}
        
        # Basic volume features
        features['packet_count'] = len(df)
        features['total_bytes'] = df['length'].sum()
        features['avg_packet_size'] = df['length'].mean()
        features['max_packet_size'] = df['length'].max()
        features['min_packet_size'] = df['length'].min()
        
        # Protocol distribution
        total = len(df)
        protocol_counts = df['protocol'].value_counts()
        features['tcp_ratio'] = protocol_counts.get('TCP', 0) / total if total > 0 else 0
        features['udp_ratio'] = protocol_counts.get('UDP', 0) / total if total > 0 else 0
        features['icmp_ratio'] = protocol_counts.get('ICMP', 0) / total if total > 0 else 0
        
        # Connection patterns
        features['unique_src_ips'] = df['src_ip'].nunique()
        features['unique_dst_ips'] = df['dst_ip'].nunique()
        features['unique_src_ports'] = df['src_port'].nunique() if 'src_port' in df else 0
        features['unique_dst_ports'] = df['dst_port'].nunique() if 'dst_port' in df else 0
        
        # Timing features
        duration = self._calculate_duration(df)
        features['duration_seconds'] = duration
        features['packets_per_second'] = len(df) / max(duration, 0.1)
        features['bytes_per_second'] = df['length'].sum() / max(duration, 0.1)
        
        # Port scan indicator
        if 'dst_port' in df and 'src_ip' in df:
            max_ports = df.groupby('src_ip')['dst_port'].nunique().max() if len(df) > 0 else 0
            features['port_scan_indicator'] = max_ports
        else:
            features['port_scan_indicator'] = 0
        
        return features
    
    def _calculate_duration(self, df):
        """Calculate time window duration"""
        if len(df) < 2 or 'timestamp' not in df:
            return 1.0
        
        try:
            timestamps = pd.to_datetime(df['timestamp'], format='%H:%M:%S')
            duration = (timestamps.max() - timestamps.min()).total_seconds()
            return max(duration, 0.1)
        except:
            return 1.0
    
    def _get_empty_features(self):
        """Return default features when no packets"""
        return {
            'packet_count': 0,
            'total_bytes': 0,
            'avg_packet_size': 0,
            'max_packet_size': 0,
            'min_packet_size': 0,
            'tcp_ratio': 0,
            'udp_ratio': 0,
            'icmp_ratio': 0,
            'unique_src_ips': 0,
            'unique_dst_ips': 0,
            'unique_src_ports': 0,
            'unique_dst_ports': 0,
            'duration_seconds': 0,
            'packets_per_second': 0,
            'bytes_per_second': 0,
            'port_scan_indicator': 0,
        }
    
    def get_feature_names(self):
        """Return list of all feature names"""
        return list(self._get_empty_features().keys())