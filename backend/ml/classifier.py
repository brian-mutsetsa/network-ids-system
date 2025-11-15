"""
Attack Classifier - Identifies types of attacks
"""

class AttackClassifier:
    """Classify network attack types using rules"""
    
    def classify(self, features, anomaly_result=None):
        """
        Classify the type of attack
        
        Args:
            features: Dictionary of extracted features
            anomaly_result: Optional anomaly detection result
            
        Returns:
            Dictionary with attack type, confidence, severity
        """
        
        # If not anomalous, return normal
        if anomaly_result and not anomaly_result.get('anomaly', False):
            return {
                'type': 'Normal Traffic',
                'confidence': 0.95,
                'severity': 'low',
                'description': 'No anomalous behavior detected',
                'recommendations': self._get_recommendations('Normal Traffic')
            }
        
        # Rule-based classification
        attack_type, confidence, severity = self._classify_by_rules(features)
        
        return {
            'type': attack_type,
            'confidence': confidence,
            'severity': severity,
            'description': self._get_description(attack_type),
            'recommendations': self._get_recommendations(attack_type)
        }
    
    def _classify_by_rules(self, features):
        """Use rules to classify attack type"""
        
        # Port Scan Detection
        if features.get('port_scan_indicator', 0) > 50:
            return 'Port Scan', 0.90, 'medium'
        if features.get('port_scan_indicator', 0) > 20:
            return 'Port Scan', 0.75, 'medium'
        
        # DDoS Detection
        if features.get('packets_per_second', 0) > 1000:
            return 'DDoS Attack', 0.85, 'critical'
        
        # High traffic volume
        if features.get('packet_count', 0) > 500:
            return 'High Traffic Volume', 0.70, 'high'
        
        # Data exfiltration
        if features.get('total_bytes', 0) > 10000000:  # 10MB
            if features.get('unique_dst_ips', 0) <= 2:
                return 'Data Exfiltration', 0.70, 'critical'
        
        # Multiple connections
        if features.get('unique_dst_ips', 0) > 50:
            return 'Scanning Activity', 0.65, 'medium'
        
        # Default
        return 'Unknown Attack', 0.50, 'medium'
    
    def _get_description(self, attack_type):
        """Get description for attack type"""
        descriptions = {
            'Port Scan': 'Attacker probing multiple ports to find open services',
            'DDoS Attack': 'Distributed Denial of Service - overwhelming traffic volume',
            'High Traffic Volume': 'Unusually high amount of network traffic detected',
            'Data Exfiltration': 'Large data transfer to external destination',
            'Scanning Activity': 'Network scanning or reconnaissance behavior',
            'Normal Traffic': 'Traffic patterns appear normal',
            'Unknown Attack': 'Anomalous behavior but unable to classify specific type'
        }
        return descriptions.get(attack_type, 'Unknown attack pattern')
    
    def _get_recommendations(self, attack_type):
        """Get mitigation recommendations"""
        recommendations = {
            'Normal Traffic': [
                'Continue monitoring network activity',
                'Maintain current security posture',
                'Review logs periodically',
                'Keep systems updated'
            ],
            'Port Scan': [
                'Enable firewall to limit port exposure',
                'Implement rate limiting on connections',
                'Monitor and log connection attempts',
                'Use intrusion prevention system'
            ],
            'DDoS Attack': [
                'Enable DDoS protection services',
                'Implement rate limiting immediately',
                'Contact ISP for upstream filtering',
                'Scale infrastructure if possible'
            ],
            'High Traffic Volume': [
                'Investigate source of traffic',
                'Check for legitimate bulk transfers',
                'Implement traffic shaping',
                'Monitor bandwidth usage'
            ],
            'Data Exfiltration': [
                'Block suspicious destination IPs immediately',
                'Implement data loss prevention (DLP)',
                'Review user access permissions',
                'Encrypt sensitive data'
            ],
            'Scanning Activity': [
                'Block scanning source IPs',
                'Review firewall rules',
                'Enable intrusion detection',
                'Monitor for follow-up attacks'
            ]
            
        }
        
        return recommendations.get(attack_type, [
            'Investigate the incident',
            'Isolate affected systems',
            'Review security logs',
            'Update security policies'
        ])