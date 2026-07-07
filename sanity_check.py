"""
Quick sanity check: run after every retrain, before trusting the model.
Flags if well-known legitimate sites score high risk, or obvious phishing
patterns score low risk.

Usage: python sanity_check.py
"""
import warnings
warnings.filterwarnings("ignore")

import joblib
from features import feature_frame
from known_safe_domains import is_known_safe
import urllib.parse

MODEL_PATH = "models/urlscope_model.joblib"

KNOWN_SAFE = [
    "https://www.google.com",
    "https://www.wikipedia.org",
    "https://www.amity.edu",
    "https://www.harvard.edu",
    "https://www.sbi.co.in",
    "https://www.hdfcbank.com",
    "https://portal.amity.edu/student/login",
    "https://netbanking.hdfcbank.com/action/login/index.html",
]

KNOWN_PHISHING_STYLE = [
    "https://secure-paypal-verify-account.tk/login",
    "http://192.168.1.1@login-verify-bank.xyz/account",
    "http://bit.ly/free-gift-claim-now",
]

THRESHOLD = 0.50


def scored_risk(model, url):
    X, _ = feature_frame(url, False)
    risk = float(model.predict_proba(X)[0, 1])
    hostname = urllib.parse.urlparse(url if "://" in url else "https://" + url).hostname or ""
    if is_known_safe(hostname):
        risk = min(risk, 0.20)
    return risk


def main():
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]

    print(f"Ensemble weights: {model.weights}")
    print(f"Estimators: {[type(e).__name__ for e in model.estimators_]}")
    print(f"Dataset used for training: {bundle.get('dataset_info')}")
    print()

    fails = 0
    print("-- Known SAFE sites (want LOW risk) --")
    for url in KNOWN_SAFE:
        risk = scored_risk(model, url)
        flag = "FAIL (false positive)" if risk >= THRESHOLD else "ok"
        if risk >= THRESHOLD:
            fails += 1
        print(f"  {risk:.3f}  {flag:<22}  {url}")

    print("\n-- Known PHISHING-style URLs (want HIGH risk) --")
    for url in KNOWN_PHISHING_STYLE:
        risk = scored_risk(model, url)
        flag = "FAIL (false negative)" if risk < THRESHOLD else "ok"
        if risk < THRESHOLD:
            fails += 1
        print(f"  {risk:.3f}  {flag:<22}  {url}")

    print(f"\n{fails} failure(s) out of {len(KNOWN_SAFE) + len(KNOWN_PHISHING_STYLE)} checks.")
    if fails:
        print("Model looks miscalibrated — do NOT deploy as-is.")
    else:
        print("Model passes basic sanity checks.")


if __name__ == "__main__":
    main()
