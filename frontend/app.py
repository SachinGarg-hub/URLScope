import sys
from pathlib import Path

# Add backend to sys.path so we can import backend modules directly
backend_path = Path(__file__).parent.parent / "backend"
sys.path.append(str(backend_path))

import html as html_lib
import re
import urllib.parse

import joblib
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

from utils import validateUrl
from features import FEATURE_ORDER, feature_frame
from train_model import train
from known_safe_domains import is_known_safe

MODEL_PATH = backend_path / "models" / "urlscope_model.joblib"
HTML_PATH = Path(__file__).parent / "index.html"

st.set_page_config(page_title="URLSCOPE", page_icon="🛡️", layout="centered")


@st.cache_resource
def load_model():
    if not MODEL_PATH.exists():
        if "mount/src" in str(Path(__file__)):
            st.error("Model not found on Streamlit Cloud. Please wait for the maintainer to upload the model.")
            st.stop()
        train()
    return joblib.load(MODEL_PATH)


def explain_with_shap(model, X):
    try:
        import shap
        # Explain the XGBoost estimator inside the ensemble when available.
        for name, estimator in model.named_estimators_.items():
            if "xgboost" in name:
                explainer = shap.TreeExplainer(estimator)
                values = explainer.shap_values(X)
                if isinstance(values, list):
                    values = values[1]
                vals = values[0]
                return pd.Series(vals, index=FEATURE_ORDER).sort_values(key=abs, ascending=False)
    except Exception:
        pass
    return pd.Series(index=FEATURE_ORDER, data=0.0)


def _is_bad(f, v) -> bool:
    """Return True when a feature value signals phishing risk."""
    return (
        (f in {"has_suspicious_tld", "has_ip", "has_at", "is_shortened", "has_forms"} and v)
        or (f == "ssl_valid" and not v)
        or (f == "url_length" and v > 65)
        or (f == "num_hyphens" and v >= 2)
        or (f == "brand_keyword_count" and v > 0)
        or (f == "domain_age_days" and (v == -1 or 0 <= v < 30))
        or (f == "external_link_ratio" and v > 0.7)
    )


def heuristic_reasons(feats, shap_values):
    labels = {
        "has_suspicious_tld": "Suspicious top-level domain", "brand_keyword_count": "Brand/risk keyword present",
        "domain_age_days": "Very new or unknown domain age", "ssl_valid": "No valid SSL certificate",
        "url_length": "Excessive URL length", "num_hyphens": "Hyphen count in domain",
        "has_ip": "IP address used as host", "has_at": "@ redirect trick present",
        "is_shortened": "Shortened link service", "has_forms": "Page contains forms",
        "external_link_ratio": "High external-link ratio", "has_https": "HTTPS present"
    }
    rows = []
    for f in FEATURE_ORDER:
        v = feats[f]
        bad = _is_bad(f, v)
        ok = (f in {"has_ip", "has_at", "has_suspicious_tld", "is_shortened"} and not v) or (f == "has_https" and v)
        if bad or ok:
            rows.append(("bad" if bad else "ok", labels.get(f, f.replace("_", " ").title()), str(v), float(shap_values.get(f, 0.0))))
    rows = sorted(rows, key=lambda r: abs(r[3]), reverse=True)[:8]
    return rows


@st.cache_data(show_spinner=False)
def scan_url(_model, url: str, live: bool):
    """Cache scan results so Streamlit widget interactions don't re-run the scan."""
    X, feats = feature_frame(url, live)
    risk = float(_model.predict_proba(X)[0, 1])
    shap_values = explain_with_shap(_model, X)

    hostname = urllib.parse.urlparse(url if "://" in url else "https://" + url).hostname or ""
    if is_known_safe(hostname):
        # Domain-reputation override: pure lexical ML can't reliably tell a
        # legitimate bank/institution login page apart from a phishing page
        # using the same words ("login", "secure", "verify"). Dampen the
        # score for recognized institutions rather than trusting keywords
        # alone. See known_safe_domains.py for details and caveats.
        risk = min(risk, 0.20)

    return X, feats, risk, shap_values


def dataset_badge_text(dataset_info):
    if not dataset_info:
        return "Trained on synthetic data"
    source = dataset_info.get("source", "synthetic")
    rows = dataset_info.get("rows")
    name = dataset_info.get("name", "")
    if source == "kaggle":
        short_name = name.split("/")[-1]
        return f"Trained on Kaggle: {short_name} ({rows:,} URLs)" if rows else f"Trained on Kaggle: {short_name}"
    if source.startswith("csv"):
        return f"Trained on {name} ({rows:,} URLs)" if rows else f"Trained on {name}"
    return f"Trained on synthetic data ({rows:,} URLs)" if rows else "Trained on synthetic data"


def render_html(url, verdict, risk, reasons, model_name="Voting ensemble", dataset_info=None):
    import jinja2
    html = HTML_PATH.read_text(encoding="utf-8")
    template = jinja2.Template(html)
    
    result_title = "Flagged — likely phishing" if verdict else "Clear — likely legitimate"
    stamp = "FLAGGED<br>PHISHING" if verdict else "LIKELY<br>SAFE"
    color = "var(--red)" if verdict else "var(--teal)"
    triggered = sum(1 for r in reasons if r[0] == "bad")
    
    rows = "\n".join([f'''<div class="ev-row"><div class="ev-flag {flag}"></div><div class="ev-name">{name}</div><div class="ev-detail">{detail}</div><div class="ev-weight">{weight:+.2f}</div></div>''' for flag, name, detail, weight in reasons])
    safe_url = html_lib.escape(url, quote=True)
    html = re.sub(r'<input type="text"[^>]*>', f'<input type="text" placeholder="https://secure-paypal-verify-account.tk/login" value="{safe_url}">', html)
    html = re.sub(r'<p class="verdict-url">.*?</p>', f'<p class="verdict-url">{safe_url}</p>', html)
    html = re.sub(r'<p class="verdict-title">.*?</p>', f'<p class="verdict-title" style="color:{color}">{result_title}</p>', html)
    html = re.sub(r'<p class="verdict-sub">.*?</p>', f'<p class="verdict-sub">{triggered} risk signals triggered</p>', html)
    html = re.sub(r'<div class="stamp">\s*<div class="stamp-text">.*?</div>\s*</div>', f'<div class="stamp" style="border-color:{color}"><div class="stamp-text" style="color:{color}">{stamp}</div></div>', html, flags=re.S)
    html = re.sub(r'<span class="value">.*?</span>', f'<span class="value" style="color:{color}">{risk:.0%}</span>', html)
    html = re.sub(r'<div class="meter-track"><div class="meter-fill"></div></div>', f'<div class="meter-track"><div class="meter-fill" style="width:{risk*100:.1f}%"></div></div>', html)
    html = re.sub(r'<div class="evidence-head"><span class="label">Feature breakdown</span></div>.*?</div>\s*<div class="model-footer">', f'<div class="evidence-head"><span class="label">Feature breakdown</span></div>{rows}</div><div class="model-footer">', html, flags=re.S)
    html = re.sub(r'<div class="pill"><div class="sw"></div>.*?</div>', f'<div class="pill"><div class="sw"></div>{model_name}</div>', html, count=1)
    # Add a dataset-provenance pill right after the model-name pill so the UI
    # always shows what data actually trained the currently-loaded model.
    badge = dataset_badge_text(dataset_info)
    
    return template.render(
        url=url,
        result_title=result_title,
        stamp=stamp,
        color=color,
        triggered=triggered,
        risk_pct=f"{risk:.0%}",
        risk_width=f"{risk*100:.1f}",
        reasons=reasons,
        model_name=model_name,
        badge=badge
    )


# ---------------------------------------------------------------------------
# Sidebar — scan controls
# ---------------------------------------------------------------------------
bundle = load_model()
model = bundle["model"]
dataset_info = bundle.get("dataset_info")

st.sidebar.title("URLSCOPE Controls")
url = st.sidebar.text_input("URL to scan", "https://secure-paypal-verify-account.tk/login")
live = st.sidebar.checkbox("Enable live domain / SSL / page checks", value=False)
show_table = st.sidebar.checkbox("Show raw feature table", value=False)

# ---------------------------------------------------------------------------
# Sidebar — dataset / retraining controls
# ---------------------------------------------------------------------------
st.sidebar.divider()
st.sidebar.title("Training data")
st.sidebar.caption(dataset_badge_text(dataset_info))

with st.sidebar.expander("Retrain from data/ CSV"):
    st.caption("Place your Kaggle CSV in the data/ folder, then retrain.")
    sample_size = st.number_input("Max rows to train on (0 = use all)", min_value=0, value=20000, step=1000)
    invert_labels = st.checkbox("Flip label polarity (use if results look backwards)", value=False)
    if st.button("Retrain from data/ CSV", type="primary"):
        status = st.empty()
        try:
            train(sample_size=sample_size or None, invert_labels=invert_labels, progress_callback=lambda msg: status.info(msg))
            st.cache_resource.clear()
            st.cache_data.clear()
            st.success("Retrained successfully. Reloading model...")
            st.rerun()
        except Exception as e:
            st.error(f"Training failed: {e}")

with st.sidebar.expander("Retrain with your own CSV"):
    uploaded = st.file_uploader("CSV with a url column and a label column", type=["csv"])
    invert_labels_csv = st.checkbox("Flip label polarity", value=False, key="invert_csv")
    if uploaded is not None and st.button("Retrain from uploaded CSV"):
        tmp_path = backend_path / "data" / uploaded.name
        tmp_path.parent.mkdir(exist_ok=True)
        tmp_path.write_bytes(uploaded.getvalue())
        status = st.empty()
        try:
            train(csv_path=str(tmp_path), invert_labels=invert_labels_csv, progress_callback=lambda msg: status.info(msg))
            st.cache_resource.clear()
            st.cache_data.clear()
            st.success("Retrained successfully. Reloading model...")
            st.rerun()
        except Exception as e:
            st.error(f"Training failed: {e}")

# ---------------------------------------------------------------------------
# Main scan panel
# ---------------------------------------------------------------------------
@st.cache_data(show_spinner=False)
def get_cached_features(url_to_check, enable_live):
    return feature_frame(url_to_check, enable_live)

X, feats = get_cached_features(url, live)
risk = float(model.predict_proba(X)[0, 1])
if not url.strip():
    st.warning("Enter a URL to scan.")
    st.stop()

with st.spinner("Running live domain checks..." if live else "Scanning URL..."):
    X, feats, risk, shap_values = scan_url(model, url, live)

verdict = risk >= 0.50
reasons = heuristic_reasons(feats, shap_values)
components.html(render_html(url, verdict, risk, reasons, dataset_info=dataset_info), height=1180, scrolling=True)

if show_table:
    st.subheader("Extracted features")
    st.dataframe(X.T.rename(columns={0: "value"}))
    st.subheader("Training metrics")
    st.dataframe(bundle["metrics"].round(4))
    if dataset_info:
        st.subheader("Dataset info")
        st.json(dataset_info)