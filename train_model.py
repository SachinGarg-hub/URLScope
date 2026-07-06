import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier, ExtraTreeClassifier
from xgboost import XGBClassifier

from features import FEATURE_ORDER, extract_features

OUT = Path("models")
OUT.mkdir(exist_ok=True)
DATA_DIR = Path("data")
DATA_DIR.mkdir(exist_ok=True)

DEFAULT_DATASET_NAME = "final_dataset_with_all_features_v3.1.csv"

URL_COLUMN_ALIASES = ["url", "urls", "link", "links", "website", "domain", "webpage"]
LABEL_COLUMN_ALIASES = ["label", "labels", "status", "class", "result", "type", "category", "target"]
PHISHING_TOKENS = {"1", "1.0", "bad", "phishing", "phish", "malicious", "malware", "defacement", "spam", "unsafe", "fraud", "fake", "true", "yes"}
SAFE_TOKENS = {"0", "0.0", "good", "benign", "legit", "legitimate", "safe", "clean", "normal", "false", "no"}


def _pick_column(columns, aliases):
    lower_map = {c.lower().strip(): c for c in columns}
    for alias in aliases:
        if alias in lower_map:
            return lower_map[alias]
    return None


def normalize_dataset(df, invert_labels=False):
    url_col = _pick_column(df.columns, URL_COLUMN_ALIASES)
    label_col = _pick_column(df.columns, LABEL_COLUMN_ALIASES)
    if url_col is None or label_col is None:
        raise ValueError(f"columns found: {list(df.columns)}")

    work = df[[url_col, label_col]].copy()
    work.columns = ["url", "label"]
    work["url"] = work["url"].astype(str).str.strip()

    def map_label(v):
        s = str(v).strip().lower()
        if s in PHISHING_TOKENS:
            return 1
        if s in SAFE_TOKENS:
            return 0
        return 1 if s else np.nan

    work["label"] = work["label"].apply(map_label)
    work = work.dropna(subset=["url", "label"])
    work["label"] = work["label"].astype(int)
    if invert_labels:
        work["label"] = 1 - work["label"]
    return work.drop_duplicates(subset=["url"]).reset_index(drop=True)


def resolve_dataset_path(path=None):
    if path:
        return Path(path)
    preferred = DATA_DIR / DEFAULT_DATASET_NAME
    if preferred.exists():
        return preferred
    csv_files = sorted(DATA_DIR.glob("*.csv"))
    if not csv_files:
        raise FileNotFoundError("No CSV found in data/. Place your dataset there or pass --csv.")
    return max(csv_files, key=lambda f: f.stat().st_size)


def load_csv_dataset(csv_path, invert_labels=False):
    df = pd.read_csv(csv_path)
    return normalize_dataset(df, invert_labels=invert_labels)


def build_models(scale_pos_weight=1.0):
    return {
        "Decision Tree": DecisionTreeClassifier(max_depth=8, random_state=42, class_weight="balanced"),
        "Random Tree": ExtraTreeClassifier(max_depth=10, random_state=42, class_weight="balanced"),
        "Logistic Regression": Pipeline([("scaler", StandardScaler()), ("model", LogisticRegression(max_iter=1000, class_weight="balanced"))]),
        "Random Forest": RandomForestClassifier(n_estimators=400, max_depth=16, random_state=42, class_weight="balanced", n_jobs=-1),
        "XGBoost": XGBClassifier(n_estimators=350, max_depth=6, learning_rate=0.05, subsample=0.9, colsample_bytree=0.9, eval_metric="logloss", random_state=42, scale_pos_weight=scale_pos_weight, n_jobs=-1),
    }


def _urls_to_features(urls, live_checks=False):
    rows, keep = [], []
    for i, u in enumerate(urls):
        try:
            rows.append(extract_features(u, live_checks))
            keep.append(i)
        except Exception:
            continue
    return pd.DataFrame(rows)[FEATURE_ORDER], keep


def train(csv_path=None, sample_size=None, invert_labels=False, live_checks=False, progress_callback=None):
    path = resolve_dataset_path(csv_path)
    if progress_callback:
        progress_callback(f"Loading {path}...")
    norm = load_csv_dataset(path, invert_labels=invert_labels)
    if sample_size and len(norm) > sample_size:
        norm = (
            norm.groupby("label", group_keys=False)
            .apply(lambda g: g.sample(min(len(g), sample_size // 2), random_state=42))
            .reset_index(drop=True)
        )
    if progress_callback:
        progress_callback(f"Extracting features for {len(norm)} URLs...")
    X, keep = _urls_to_features(norm["url"], live_checks)
    y = norm["label"].astype(int).iloc[keep].reset_index(drop=True)
    dataset_info = {"source": "csv", "name": path.name, "rows": int(len(norm)), "phishing": int((y == 1).sum()), "safe": int((y == 0).sum())}

    if progress_callback:
        progress_callback("Splitting train/test and fitting models...")

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.22, random_state=42, stratify=y)
    scale_pos_weight = float((y_train == 0).sum()) / max(1, int((y_train == 1).sum()))
    models = build_models(scale_pos_weight=scale_pos_weight)
    fitted, metrics = [], []
    weights = []
    for name, model in models.items():
        model.fit(X_train, y_train)
        pred = model.predict(X_test)
        prob = model.predict_proba(X_test)[:, 1]
        f1 = f1_score(y_test, pred)
        metrics.append({"model": name, "accuracy": accuracy_score(y_test, pred), "precision": precision_score(y_test, pred), "recall": recall_score(y_test, pred), "f1": f1, "roc_auc": roc_auc_score(y_test, prob)})
        fitted.append((name.lower().replace(" ", "_"), model))
        weights.append(f1)
        try:
            model.fit(X_train, y_train)
            pred = model.predict(X_test)
            prob = model.predict_proba(X_test)[:, 1]
            metrics.append({"model": name, "accuracy": accuracy_score(y_test, pred), "precision": precision_score(y_test, pred), "recall": recall_score(y_test, pred), "f1": f1_score(y_test, pred), "roc_auc": roc_auc_score(y_test, prob)})
            fitted.append((name.lower().replace(" ", "_"), model))
        except Exception as exc:
            if progress_callback:
                progress_callback(f"Skipping {name}: {exc}")

    if progress_callback:
        progress_callback("Fitting voting ensemble...")

    ensemble = VotingClassifier(estimators=fitted, voting="soft", weights=weights)
    f1_weights = [m["f1"] for m in metrics]
    ensemble = VotingClassifier(estimators=fitted, voting="soft", weights=f1_weights)
    ensemble.fit(X_train, y_train)

    ens_pred = ensemble.predict(X_test)
    ens_prob = ensemble.predict_proba(X_test)[:, 1]
    metrics.append({
        "model": "Voting Ensemble (deployed)",
        "accuracy": accuracy_score(y_test, ens_pred),
        "precision": precision_score(y_test, ens_pred),
        "recall": recall_score(y_test, ens_pred),
        "f1": f1_score(y_test, ens_pred),
        "roc_auc": roc_auc_score(y_test, ens_prob),
    })

    joblib.dump({"model": ensemble, "features": FEATURE_ORDER, "metrics": pd.DataFrame(metrics), "dataset_info": dataset_info}, OUT / "urlscope_model.joblib", compress=9)
    pd.DataFrame(metrics).to_csv(OUT / "metrics.csv", index=False)
    with open(OUT / "dataset_info.json", "w") as f:
        json.dump(dataset_info, f, indent=2)

    return pd.DataFrame(metrics), dataset_info


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--csv", type=str, default=None)
    parser.add_argument("--invert-labels", action="store_true")
    parser.add_argument("--sample-size", type=int, default=None)
    parser.add_argument("--live-checks", action="store_true")
    args = parser.parse_args()

    metrics_df, info = train(csv_path=args.csv, sample_size=args.sample_size, invert_labels=args.invert_labels, live_checks=args.live_checks, progress_callback=print)
    print(info)
    print(metrics_df.round(4))