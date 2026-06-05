import os
import joblib
from features import extract_features, calculate_shannon_entropy

MODEL_PATH = "dns_rf_model.pkl"

_model = None


def _load_model():
    global _model
    if _model is None and os.path.exists(MODEL_PATH):
        _model = joblib.load(MODEL_PATH)
    return _model


def classify_dns_query(query_string: str):
    """
    Returns (entropy_score, label, risk_score).
    Uses trained Random Forest when available; falls back to rule-based thresholds.
    """
    entropy = calculate_shannon_entropy(query_string)
    model = _load_model()

    if model is not None:
        feat = extract_features(query_string)
        prob = model.predict_proba([feat])[0]
        label = "Tunneling" if prob[1] >= 0.5 else "Benign"
        risk_score = round(prob[1] * 100, 1)
    else:
        # Fallback: rule-based (for use before train_model.py is run)
        if entropy > 4.2 or len(query_string) > 45:
            label = "Tunneling"
            risk_score = min(99.9, round(40.0 + entropy * 10.0 + len(query_string) * 0.2, 1))
        else:
            label = "Benign"
            risk_score = round(10.0 + entropy * 5.0, 1)

    return entropy, label, risk_score
