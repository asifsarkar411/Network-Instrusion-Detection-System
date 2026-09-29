"""
Hybrid Analysis Engine
=======================
Combines ML model predictions with rule-based detection
using weighted fusion for final attack classification.

Architecture:
  Flow Features → ML Model → ML Score (0-1)
  Flow Features → Rule Engine → Rule Score (0-1)
  Final = (W_rule × Rule) + (W_ml × ML)
  
Configurable via config.yaml:
  - rule_weight
  - ml_weight  
  - alert_threshold
"""

import os
import pickle
import warnings
from typing import Dict, Optional, List
import numpy as np
import yaml

from src.rule_engine import RuleEngine

warnings.filterwarnings("ignore")


class HybridDetector:
    """
    Combines ML and rule-based detection for robust NIDS classification.
    
    Uses weighted fusion:
      Final Score = (rule_weight × rule_score) + (ml_weight × ml_score)
    
    Alert severity levels:
      - high:   final_score >= 0.85
      - medium: final_score >= threshold (default 0.7)
      - low:    final_score < threshold
    """
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        Initialize the hybrid detector.
        
        Loads ML model, scaler, label encoder, and rule engine.
        Reads weights and threshold from config.yaml.
        
        Args:
            config_path: Path to configuration YAML file
        """
        # Load config
        with open(config_path, "r") as f:
            self.config = yaml.safe_load(f)
        
        analysis_config = self.config.get("analysis", {})
        self.rule_weight = analysis_config.get("rule_weight", 0.4)
        self.ml_weight = analysis_config.get("ml_weight", 0.6)
        self.alert_threshold = analysis_config.get("alert_threshold", 0.7)
        
        # Normalize weights
        total = self.rule_weight + self.ml_weight
        if total != 1.0:
            self.rule_weight /= total
            self.ml_weight /= total
        
        print(f"[HybridDetector] Weights — Rule: {self.rule_weight:.2f}, ML: {self.ml_weight:.2f}")
        print(f"[HybridDetector] Alert threshold: {self.alert_threshold:.2f}")
        
        # Load ML model artifacts
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self._load_ml_artifacts()
        
        # Initialize rule engine
        self.rule_engine = RuleEngine()
        
        # Alert history for deduplication
        self.recent_alerts: List[Dict] = []
        self.max_recent_alerts = 100
        
        # Statistics
        self.total_flows_analyzed = 0
        self.total_alerts_generated = 0
    
    def _load_ml_artifacts(self) -> None:
        """Load trained model, scaler, and encoder from disk."""
        model_dir = "models"
        
        try:
            with open(os.path.join(model_dir, "nids_xgboost.pkl"), "rb") as f:
                self.model = pickle.load(f)
            print("[HybridDetector] XGBoost model loaded")
        except FileNotFoundError:
            print("[HybridDetector] WARNING: ML model not found. Using rules only.")
            self.ml_weight = 0.0
            self.rule_weight = 1.0
        
        try:
            with open(os.path.join(model_dir, "scaler.pkl"), "rb") as f:
                self.scaler = pickle.load(f)
        except FileNotFoundError:
            self.scaler = None
        
        try:
            with open(os.path.join(model_dir, "label_encoder.pkl"), "rb") as f:
                self.label_encoder = pickle.load(f)
        except FileNotFoundError:
            self.label_encoder = None
        
        try:
            with open(os.path.join(model_dir, "feature_names.pkl"), "rb") as f:
                self.feature_names = pickle.load(f)
        except FileNotFoundError:
            self.feature_names = None
    
    def _get_ml_score(self, flow_features: Dict) -> Dict:
        """
        Get ML model prediction for a flow.
        
        Args:
            flow_features: Dict of flow features from FlowExtractor
            
        Returns:
            Dict with 'score', 'predicted_class', 'all_scores'
        """
        if self.model is None or self.scaler is None:
            return {"score": 0.0, "predicted_class": None, "all_scores": {}}
        
        try:
            # Build feature vector matching training feature order
            feature_vector = []
            missing_count = 0
            
            for feat_name in self.feature_names:
                if feat_name in flow_features:
                    feature_vector.append(flow_features[feat_name])
                else:
                    feature_vector.append(0.0)
                    missing_count += 1
            
            if missing_count > len(self.feature_names) * 0.5:
                # Too many missing features — unreliable prediction
                return {"score": 0.0, "predicted_class": None, "all_scores": {}}
            
            # Scale and predict
            X = np.array([feature_vector])
            X_scaled = self.scaler.transform(X)
            
            # Get probabilities
            proba = self.model.predict_proba(X_scaled)[0]
            max_idx = np.argmax(proba)
            max_score = proba[max_idx]
            
            # Get class name
            if self.label_encoder:
                predicted_class = self.label_encoder.classes_[max_idx]
            else:
                predicted_class = str(max_idx)
            
            # Build all scores dict
            all_scores = {}
            if self.label_encoder:
                for i, cls in enumerate(self.label_encoder.classes_):
                    all_scores[cls] = float(proba[i])
            
            # Convert to attack confidence (1.0 if predicted as attack, Benign probability if Benign)
            if predicted_class == "Benign":
                ml_confidence = 0.0  # Benign prediction = no attack signal
            else:
                ml_confidence = max_score  # Attack prediction = use confidence
            
            return {
                "score": float(ml_confidence),
                "predicted_class": predicted_class,
                "all_scores": all_scores,
            }
            
        except Exception as e:
            print(f"[HybridDetector] ML prediction error: {e}")
            return {"score": 0.0, "predicted_class": None, "all_scores": {}}
    
    def _get_rule_score(self, flow_features: Dict) -> Dict:
        """
        Get rule engine score for a flow.
        
        Args:
            flow_features: Dict of flow features
            
        Returns:
            Dict with 'score', 'detected_type', 'details'
        """
        result = self.rule_engine.evaluate_flow(flow_features)
        
        return {
            "score": result.get("max_score", 0.0),
            "detected_type": result.get("detected_type"),
            "portscan_score": result.get("portscan_score", 0.0),
            "dos_score": result.get("dos_score", 0.0),
            "webattack_score": result.get("webattack_score", 0.0),
        }
    
    def analyze_flow(self, flow_features: Dict) -> Dict:
        """
        Analyze a flow using both ML and rule engine, then fuse scores.
        
        This is the main entry point for flow-based detection.
        
        Args:
            flow_features: Dict with flow features (25 keys from Phase 1)
            
        Returns:
            Dict with complete analysis results:
                - final_score: fused confidence (0-1)
                - is_alert: whether threshold is exceeded
                - severity: 'high', 'medium', or 'low'
                - attack_type: predicted attack category
                - ml_result: ML prediction details
                - rule_result: rule engine details
        """
        self.total_flows_analyzed += 1
        
        # Get individual scores
        ml_result = self._get_ml_score(flow_features)
        rule_result = self._get_rule_score(flow_features)
        
        ml_score = ml_result["score"]
        rule_score = rule_result["score"]
        
        # If rule engine is highly confident and ML has no strong opinion,
        # let the rule engine dominate
        if rule_score > 0.8 and ml_score < 0.1:
            final_score = rule_score  # Trust the rule engine
        else:
            final_score = (self.rule_weight * rule_score) + (self.ml_weight * ml_score)
        final_score = min(final_score, 1.0)  # Cap at 1.0
        
        # Determine attack type
        attack_type = None
        if final_score >= self.alert_threshold:
            # Prefer ML prediction for behavioral attacks, rule for web attacks
            if rule_result.get("webattack_score", 0) > 0.5:
                attack_type = "WebAttack"
            elif ml_result["predicted_class"] and ml_result["predicted_class"] != "Benign":
                attack_type = ml_result["predicted_class"]
            elif rule_result["detected_type"]:
                attack_type = rule_result["detected_type"].capitalize()
        
        # Determine severity
        if final_score >= 0.85:
            severity = "high"
        elif final_score >= self.alert_threshold:
            severity = "medium"
        else:
            severity = "low"
        
        is_alert = final_score >= self.alert_threshold
        
        if is_alert:
            self.total_alerts_generated += 1
        
        result = {
            "final_score": round(final_score, 4),
            "is_alert": is_alert,
            "severity": severity,
            "attack_type": attack_type,
            "ml_result": {
                "score": round(ml_score, 4),
                "predicted_class": ml_result["predicted_class"],
                "all_scores": ml_result.get("all_scores", {}),
            },
            "rule_result": {
                "score": round(rule_score, 4),
                "detected_type": rule_result["detected_type"],
                "portscan_score": round(rule_result.get("portscan_score", 0), 4),
                "dos_score": round(rule_result.get("dos_score", 0), 4),
                "webattack_score": round(rule_result.get("webattack_score", 0), 4),
            },
        }
        
        # Store in recent alerts if triggered
        if is_alert:
            self.recent_alerts.append(result)
            if len(self.recent_alerts) > self.max_recent_alerts:
                self.recent_alerts.pop(0)
        
        return result
    
    def analyze_packet(self, packet, flow_features: Optional[Dict] = None) -> Dict:
        """
        Analyze a raw packet for real-time detection.
        
        Combines packet-level rule evaluation with any available flow context.
        
        Args:
            packet: Scapy Packet object
            flow_features: Optional flow features for context
            
        Returns:
            Same structure as analyze_flow()
        """
        # Get rule engine packet-level result
        packet_result = self.rule_engine.evaluate_packet(packet)
        
        rule_score = 0.0
        if packet_result["portscan_alert"]:
            rule_score = 0.9
        elif packet_result["dos_alert"]:
            rule_score = 0.9
        elif packet_result["webattack_alert"]:
            rule_score = 0.95
        
        # If flow features available, use ML too
        ml_score = 0.0
        ml_predicted = None
        if flow_features:
            ml_result = self._get_ml_score(flow_features)
            ml_score = ml_result["score"]
            ml_predicted = ml_result["predicted_class"]
        
        # Fusion
        if rule_score > 0.8 and ml_score < 0.1:
            final_score = rule_score  # Trust the rule engine
        else:
            final_score = (self.rule_weight * rule_score) + (self.ml_weight * ml_score)
        final_score = min(final_score, 1.0)
        
        attack_type = None
        if packet_result["webattack_alert"]:
            attack_type = f"WebAttack ({packet_result.get('webattack_type', 'Unknown')})"
        elif packet_result["portscan_alert"]:
            attack_type = "PortScan"
        elif packet_result["dos_alert"]:
            attack_type = "DoS"
        elif ml_predicted and ml_predicted != "Benign":
            attack_type = ml_predicted
        
        severity = "high" if final_score >= 0.85 else "medium" if final_score >= self.alert_threshold else "low"
        is_alert = final_score >= self.alert_threshold
        
        return {
            "final_score": round(final_score, 4),
            "is_alert": is_alert,
            "severity": severity,
            "attack_type": attack_type,
            "ml_result": {"score": round(ml_score, 4), "predicted_class": ml_predicted},
            "rule_result": {
                "score": round(rule_score, 4),
                "portscan_alert": packet_result["portscan_alert"],
                "dos_alert": packet_result["dos_alert"],
                "webattack_alert": packet_result["webattack_alert"],
                "webattack_type": packet_result.get("webattack_type"),
            },
        }
    
    def get_recent_alerts(self, limit: int = 20) -> List[Dict]:
        """Return recent alerts, newest first."""
        return list(reversed(self.recent_alerts[-limit:]))
    
    def get_stats(self) -> Dict:
        """Return detector statistics."""
        return {
            "flows_analyzed": self.total_flows_analyzed,
            "alerts_generated": self.total_alerts_generated,
            "alert_rate": (
                self.total_alerts_generated / self.total_flows_analyzed
                if self.total_flows_analyzed > 0 else 0
            ),
            "rule_weight": self.rule_weight,
            "ml_weight": self.ml_weight,
            "threshold": self.alert_threshold,
            "rule_engine_stats": self.rule_engine.get_stats(),
        }
    
    def reset(self) -> None:
        """Reset all state."""
        self.rule_engine.reset()
        self.recent_alerts = []
        self.total_flows_analyzed = 0
        self.total_alerts_generated = 0
    
    def update_weights(self, rule_weight: float = None, ml_weight: float = None) -> None:
        """Update fusion weights at runtime."""
        if rule_weight is not None:
            self.rule_weight = rule_weight
        if ml_weight is not None:
            self.ml_weight = ml_weight
        total = self.rule_weight + self.ml_weight
        if total > 0:
            self.rule_weight /= total
            self.ml_weight /= total
