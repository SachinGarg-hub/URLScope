"""
Run this against your own training CSV to check whether the 'safe' and
'phishing' classes are actually comparable in structure, or whether the
model is learning a dataset artifact (e.g. scheme presence, url length)
instead of real phishing signal.

Usage:
    python diagnose_dataset.py "data/dataset_with_all_features v2.csv"
"""
import sys
import pandas as pd
from train_model import load_csv_dataset
from features import extract_features, FEATURE_ORDER

def main(csv_path):
    norm = load_csv_dataset(csv_path)
    print(f"Total rows: {len(norm)}  safe={ (norm['label']==0).sum() }  phishing={ (norm['label']==1).sum() }\n")

    # Raw string-level check: does the ORIGINAL url string include a scheme?
    has_scheme = norm["url"].str.match(r"^[a-zA-Z]+://")
    print("Fraction of URLs with explicit http(s):// scheme, by class:")
    print(norm.assign(has_scheme=has_scheme).groupby("label")["has_scheme"].mean())
    print()

    # Sample raw strings from each class so you can eyeball formatting differences
    print("Sample SAFE (label=0) url strings:")
    print(norm[norm.label == 0]["url"].sample(8, random_state=1).to_list())
    print("\nSample PHISHING (label=1) url strings:")
    print(norm[norm.label == 1]["url"].sample(8, random_state=1).to_list())
    print()

    # Feature-level distribution check (sampled for speed)
    sample = pd.concat([g.sample(min(len(g), 5000), random_state=1) for _, g in norm.groupby("label")])
    rows = [extract_features(u, False) for u in sample["url"]]
    feat_df = pd.DataFrame(rows)
    feat_df["label"] = sample["label"].values

    print("Mean feature value per class (sampled 5000/class):")
    print(feat_df.groupby("label")[FEATURE_ORDER].mean().T)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/dataset_with_all_features v2.csv"
    main(path)