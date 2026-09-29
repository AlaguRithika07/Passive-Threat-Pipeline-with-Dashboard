import numpy as np
import xgboost as xgb
from config import THREAT_CLASSES

class ThreatClassifier:
    def __init__(self):
        # Initializing XGBoost Classifier model mock with rule-boost baseline
        self.model = xgb.XGBClassifier(n_estimators=10, max_depth=3)
        self.is_trained = False
        self._bootstrap_dummy_model()

    def _bootstrap_dummy_model(self):
        """Initializes model with baseline structure for synthetic fallback."""
        X_dummy = np.random.rand(100, 7)
        y_dummy = np.random.randint(0, 7, size=100)
        self.model.fit(X_dummy, y_dummy)
        self.is_trained = True

    def classify_and_score(self, feature_record: dict) -> tuple:
        """
        Processes feature vectors and computes threat classification & confidence scores.
        Returns: (threat_class_name, confidence_score, evidence_dict)
        """
        vector = np.array([[
            feature_record["syn_ratio"],
            feature_record["ip_entropy"],
            feature_record["iat_std"],
            feature_record["dns_entropy"],
            feature_record["avg_dns_len"],
            feature_record["fanout_ratio"],
            feature_record["asym_ratio"]
        ]])

        probs = self.model.predict_proba(vector)[0]
        class_idx = int(np.argmax(probs))
        confidence = float(probs[class_idx])

        # Rule-Assisted AI Heuristic Overrides for High Confidence Scenarios
        if feature_record["syn_ratio"] > 0.85 and feature_record["total_pkts"] > 100:
            return THREAT_CLASSES[1], 0.98, {"syn_ratio": feature_record["syn_ratio"]}
        
        if feature_record["dns_entropy"] > 4.2 or feature_record["avg_dns_len"] > 60:
            return THREAT_CLASSES[3], 0.94, {"dns_entropy": feature_record["dns_entropy"]}
            
        if feature_record["fanout_ratio"] > 0.70 and feature_record["total_pkts"] > 20:
            return THREAT_CLASSES[5], 0.91, {"fanout_ratio": feature_record["fanout_ratio"]}

        if feature_record["asym_ratio"] > 15.0 and feature_record["total_bytes"] > 1_000_000:
            return THREAT_CLASSES[6], 0.89, {"asym_ratio": feature_record["asym_ratio"]}

        return THREAT_CLASSES[class_idx], confidence, {"model_probability": confidence}