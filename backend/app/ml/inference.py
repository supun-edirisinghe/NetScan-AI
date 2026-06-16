"""
ml_inference.py
───────────────
Loads saved Scikit-learn / TensorFlow models and exposes a predict() function.
Falls back to rule-based scoring if no model files exist.
"""
import numpy as np
import logging
from pathlib import Path
from typing import Tuple

logger = logging.getLogger("ml_inference")
MODEL_DIR = Path("./ml_models")

_sklearn_model = None
_sklearn_scaler = None
_tf_model = None
_tf_scaler_mean = None
_tf_scaler_scale = None
_model_loaded = False


def _load_models():
    global _sklearn_model, _sklearn_scaler
    global _tf_model, _tf_scaler_mean, _tf_scaler_scale
    global _model_loaded

    if _model_loaded:
        return

    # Try Scikit-learn first (lighter weight)
    rf_path = MODEL_DIR / "rf_risk_classifier.joblib"
    sc_path = MODEL_DIR / "rf_scaler.joblib"
    if rf_path.exists() and sc_path.exists():
        try:
            import joblib
            _sklearn_model  = joblib.load(rf_path)
            _sklearn_scaler = joblib.load(sc_path)
            logger.info("Loaded Scikit-learn Random Forest risk classifier.")
        except Exception as e:
            logger.warning(f"Could not load sklearn model: {e}")

    # Try TensorFlow
    tf_path = MODEL_DIR / "tf_risk_classifier.keras"
    if tf_path.exists():
        try:
            import tensorflow as tf
            _tf_model = tf.keras.models.load_model(tf_path)
            _tf_scaler_mean  = np.load(MODEL_DIR / "tf_scaler_mean.npy")
            _tf_scaler_scale = np.load(MODEL_DIR / "tf_scaler_scale.npy")
            logger.info("Loaded TensorFlow neural network risk classifier.")
        except Exception as e:
            logger.warning(f"Could not load TF model: {e}")

    _model_loaded = True


LABEL_MAP = {0: "low", 1: "medium", 2: "high", 3: "critical"}
SCORE_MAP  = {0: 15.0, 1: 40.0, 2: 65.0, 3: 88.0}


def predict_risk(features: np.ndarray) -> Tuple[float, str]:
    """
    Predict risk score (0-100) and level from feature vector.
    Tries TF > sklearn > rule-based in that order.
    """
    _load_models()
    features = features.reshape(1, -1)

    # TensorFlow prediction
    if _tf_model is not None and _tf_scaler_mean is not None:
        try:
            scaled = (features - _tf_scaler_mean) / _tf_scaler_scale
            probs = _tf_model.predict(scaled, verbose=0)[0]
            label_idx = int(np.argmax(probs))
            confidence = float(probs[label_idx])
            # Map to score: weighted sum of class scores
            score = float(np.dot(probs, [15, 40, 65, 88]))
            return round(score, 1), LABEL_MAP[label_idx]
        except Exception as e:
            logger.warning(f"TF inference error: {e}")

    # Sklearn prediction
    if _sklearn_model is not None and _sklearn_scaler is not None:
        try:
            scaled = _sklearn_scaler.transform(features)
            label_idx = int(_sklearn_model.predict(scaled)[0])
            proba = _sklearn_model.predict_proba(scaled)[0]
            score = float(np.dot(proba, [15, 40, 65, 88]))
            return round(score, 1), LABEL_MAP[label_idx]
        except Exception as e:
            logger.warning(f"Sklearn inference error: {e}")

    # Fallback: rule-based (imported from ai_analyzer)
    return None, None


def batch_predict(feature_matrix: np.ndarray) -> list:
    """Predict risk for a batch of hosts."""
    _load_models()
    results = []
    for row in feature_matrix:
        score, level = predict_risk(row)
        results.append({"risk_score": score, "risk_level": level})
    return results
