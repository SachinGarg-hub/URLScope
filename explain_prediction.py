"""
Explains WHY a given URL got a high/low risk score, using SHAP on the
underlying tree models of the voting ensemble (XGBoost + Random Forest).
This tells us exactly which features are pushing false positives up,
instead of guessing.

Usage:
    python explain_prediction.py "https://www.google.com"
"""
import sys
import warnings
warnings.filterwarnings("ignore")

import joblib
import numpy as np
from features import feature_frame, FEATURE_ORDER

MODEL_PATH = "models/urlscope_model.joblib"


def main(url):
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    X, feats = feature_frame(url, False)

    print(f"URL: {url}")
    print(f"Ensemble risk score: {model.predict_proba(X)[0, 1]:.3f}\n")

    print("Raw feature values for this URL:")
    for k in FEATURE_ORDER:
        print(f"  {k:22s} = {feats[k]}")
    print()

    import shap

    for name, est in model.named_estimators_.items():
        if name in ("xgboost", "random_forest", "decision_tree", "random_tree"):
            print(f"-- SHAP for {name} --")
            try:
                explainer = shap.TreeExplainer(est)
                sv = explainer.shap_values(X)
                # sv can be a list (per-class) or array depending on model/version
                if isinstance(sv, list):
                    sv = sv[1]  # class 1 = phishing
                sv = np.array(sv).reshape(-1)
                pairs = sorted(zip(FEATURE_ORDER, sv), key=lambda p: -abs(p[1]))
                for feat_name, val in pairs[:8]:
                    direction = "→ pushes risk UP" if val > 0 else "→ pushes risk DOWN"
                    print(f"    {feat_name:22s} shap={val:+.3f}  {direction}")
            except Exception as exc:
                print(f"    (skipped: {exc})")
            print()


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "https://www.google.com"
    main(url)