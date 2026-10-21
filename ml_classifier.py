"""
PhishNet AI - Machine Learning Prediction Service
Module: ml_classifier.py

Safely loads the trained Random Forest model and provides inference for submitted URLs.
"""

import os
import joblib
import numpy as np
import detector

MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "phishing_model.joblib")
_MODEL = None
_MODEL_LOADED = False


def load_model():
    """Attempts to load the serialized ML model into memory."""
    global _MODEL, _MODEL_LOADED
    if _MODEL_LOADED and _MODEL is not None:
        return _MODEL

    if os.path.exists(MODEL_PATH):
        try:
            _MODEL = joblib.load(MODEL_PATH)
            _MODEL_LOADED = True
            return _MODEL
        except Exception as e:
            print(f"[!] Warning: Could not load ML model: {e}")
            _MODEL_LOADED = False
            return None
    return None


def predict_url(raw_url: str) -> dict:
    """
    Evaluates a URL using the trained ML model.
    Returns prediction ('Phishing' or 'Legitimate'), confidence score (0.0 to 1.0),
    and whether the ML model was available.
    """
    model = load_model()
    if model is None:
        return {
            "available": False,
            "prediction": "Model Not Loaded",
            "confidence": 0.0,
            "class_label": -1
        }

    try:
        features = np.array([detector.extract_features_vector(raw_url)])
        pred = model.predict(features)[0]
        probas = model.predict_proba(features)[0]

        # probas[1] is probability of Phishing
        phishing_prob = float(probas[1])
        legit_prob = float(probas[0])

        if pred == 1:
            label = "Phishing"
            confidence = phishing_prob
        else:
            label = "Legitimate"
            confidence = legit_prob

        return {
            "available": True,
            "prediction": label,
            "confidence": round(confidence, 3),
            "phishing_probability": round(phishing_prob, 3),
            "class_label": int(pred)
        }
    except Exception as e:
        return {
            "available": False,
            "prediction": f"Inference Error: {str(e)}",
            "confidence": 0.0,
            "class_label": -1
        }
