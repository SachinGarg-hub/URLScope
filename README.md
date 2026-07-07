
# URLScope — Intelligent Phishing URL Detection Platform

**Live App:** [https://urlscope.streamlit.app/](https://urlscope.streamlit.app/)

## Overview

URLScope is an intelligent phishing URL detection platform designed to identify malicious websites **before user interaction**. The system analyzes **lexical**, **domain**, and **behavioral** URL features using machine learning algorithms to classify URLs as **safe** or **phishing**.

The platform provides not only prediction results but also explainability using **SHAP (SHapley Additive exPlanations)**, allowing users to understand why a URL was classified as suspicious. It also includes a **domain-reputation allowlist** layer that works alongside the ML model, since pure lexical/keyword-based detection alone cannot reliably separate legitimate banking/institutional login pages from phishing pages that use the same words ("login", "secure", "verify").

---

## Problem Statement

Phishing attacks are among the most common cyber threats, where attackers create fake websites to steal sensitive information such as:

* User credentials
* Banking details
* Credit card information
* Personal identity data

Traditional blacklists often fail to detect newly created phishing domains. This project solves that problem using machine learning–based detection, combined with a lightweight domain-reputation layer for known institutions.

---

## Features

* Real-time phishing URL detection
* Lexical URL analysis
* Domain reputation checks (curated allowlist for well-known institutions)
* Behavioral feature extraction
* Risk confidence scoring
* SHAP-based model explainability
* Interactive web interface
* Multiple ML model comparison
* Performance-weighted voting ensemble (weak models contribute less automatically)
* Diagnostic tooling for dataset bias and false-positive debugging (see below)

---

## Technologies Used

* Python 3.x
* Scikit-learn
* Pandas
* XGBoost
* SHAP
* Streamlit
* HTML / CSS

---

## Dataset

The models are trained on a **Malicious URL Detection Dataset** (`dataset_with_all_features v2.csv`), sourced from Kaggle.

* **~640,000 raw URLs**, class distribution ~67% safe / ~33% phishing
* Augmented at training time (see `train_model.py`) with:
  * Bare root-domain examples derived from the existing safe URLs, since the raw dataset's "safe" class consists almost entirely of deep-path content pages (blog posts, profile pages, etc.) and contains virtually no plain-homepage examples
  * A small curated list of well-known global and India-relevant safe domains (`known_safe_domains.py`)
* Final training set after augmentation: **~769,000 rows**

> If you swap in a different or newer dataset version, re-run `diagnose_dataset.py` first to check for the same kind of class-wise structural skew described below.

---

## Machine Learning Algorithms

The following algorithms are implemented and compared:

### 1. Decision Tree
A supervised learning model that makes predictions using tree-based rules. Trained with `class_weight="balanced"` to counter class imbalance.

### 2. Random Tree (`ExtraTreeClassifier`)
An extremely randomized tree variant used as an additional, faster-training ensemble member.

### 3. Logistic Regression
A statistical classification model that predicts phishing probability.

### 4. Random Forest
An ensemble of multiple decision trees that improves prediction accuracy and reduces overfitting. 400 trees, max depth 16, `n_jobs=-1` for faster training.

### 5. XGBoost
A high-performance gradient boosting model. 350 trees, max depth 6, with `scale_pos_weight` computed automatically from the train-split class ratio to counter imbalance.

### 6. Voting Ensemble (deployed)
A soft-voting ensemble over all five models above, weighted by each model's own validation F1 score, so weaker learners don't drag down stronger ones. This is the model actually saved and used by the app.

---

## Handling Class Imbalance

Since the dataset is ~67% safe / ~33% phishing, plain accuracy can be misleading. To address this:

* `class_weight="balanced"` is applied to Decision Tree and Random Tree
* `scale_pos_weight` is applied to XGBoost, computed automatically from the actual train-split ratio
* Model comparison is judged primarily on **F1 and ROC-AUC**, not raw accuracy

---

## Feature Extraction

Features are computed from the URL string in a **scheme-independent (canonical) form** — length, digit count, special-character count, dot count, and entropy are computed after stripping the URL scheme, so whether the original string happened to include `http://`/`https://` doesn't leak into the numeric features. This was a necessary fix (see Debugging Journey below).

### Lexical Features
* URL length, hostname length, path length
* Number of dots, hyphens, digits, special characters
* Presence of `@`, IP-address hostnames
* Brand/risk keyword counts (word-boundary matched)
* Subdomain count, query parameter count, entropy

### Domain Features
* Domain age, SSL certificate validity (only computed when live checks are enabled)
* Suspicious TLD detection
* URL-shortener detection
* Domain-reputation allowlist match (`known_safe_domains.py`)

### Behavioral Features (only when live checks are enabled)
* Reachability
* Presence of forms
* External link ratio

---

## Domain-Reputation Allowlist

`known_safe_domains.py` holds a small, explicit, auditable list of well-known institutions (major global sites, Indian banks, `.edu`/`.ac.in`/`.gov.in` domains). At runtime, `app.py` checks the **registrable domain** (e.g. `hdfcbank.com` from `netbanking.hdfcbank.com`) against this list and caps the risk score for genuine matches — this is what lets legitimate bank/college login pages (which legitimately contain words like "login", "secure", "verify") score correctly as safe, without letting a lookalike domain like `hdfcbank-verify-login.tk` slip through, since matching is on the exact registrable domain, not a substring.

This list is a project-scoped mitigation, not a substitute for a real threat-intel feed — extend it as needed for your use case.

---

## Debugging Journey — Notable Issues Found & Fixed

During development, the deployed model was found to flag **almost all URLs, including well-known legitimate sites, as high-risk phishing**. Root-causing this surfaced several distinct issues, documented here since they're instructive for anyone extending this project:

1. **Stale model artifact** — the committed `.joblib` had been trained by an older version of `train_model.py` (unweighted voting, mismatched dataset reference in docs) and didn't reflect the current pipeline. *Fix: retrain from current code.*
2. **Duplicate model-fit bug** — each base model was being fit and appended to the ensemble twice in a loop, with dead code immediately overwriting the ensemble. *Fix: cleaned up the training loop.*
3. **Scheme-presence leakage** — ~92% of "safe" URLs in the raw dataset were stored without an `http(s)://` prefix, versus ~67% of "phishing" URLs having one. The model learned "has a scheme" as a phishing signal, which is a data-collection artifact, not a real one. *Fix: compute length/composition features on a canonical, scheme-stripped form; drop `has_https` as an unreliable trained feature.*
4. **Sampling gap (the main cause)** — the "safe" class was built entirely from deep-path content pages (blog posts, profile pages) and contained essentially **no bare-homepage examples**. A plain root domain like `google.com` (`path_length=0`) had never been seen as a safe example, only as an occasional malicious one (e.g. `sakarta.ga`). Confirmed via SHAP: `path_length` was the single largest driver pushing well-known root domains toward "phishing". *Fix: augment training data with root-domain versions of existing safe URLs plus a curated known-safe list.*
5. **Residual keyword overlap** — legitimate banking/portal login pages (e.g. `netbanking.hdfcbank.com/.../login`) genuinely contain words like "login"/"secure" that also appear in phishing URLs, which a purely lexical model can't disambiguate. *Fix: domain-reputation allowlist override at the app layer (see above), the same mitigation strategy used by real-world tools like Google Safe Browsing alongside ML.*

### Diagnostic scripts added

| Script | Purpose |
|---|---|
| `sanity_check.py` | Runs the deployed model + allowlist against a small hand-picked set of known-safe and known-phishing-style URLs; flags false positives/negatives before you trust a retrain. |
| `diagnose_dataset.py` | Inspects your training CSV directly — class-wise mean feature values, scheme-presence ratio, and sample raw URL strings per class, to catch dataset artifacts like the ones above. |
| `explain_prediction.py` | Runs SHAP on a single URL against each base estimator in the ensemble, showing exactly which features are pushing the score up or down. |

Run these after every retrain, especially if you swap in a new dataset version.

---

## Project Structure

```bash
URLScope/
│
├── app.py
├── features.py
├── train_model.py
├── known_safe_domains.py
├── sanity_check.py
├── diagnose_dataset.py
├── explain_prediction.py
├── index.html
├── requirements.txt
├── models/
│   ├── urlscope_model.joblib
│   ├── dataset_info.json
│   └── metrics.csv
├── data/
│   └── dataset_with_all_features v2.csv
├── utils/
│   └── validateUrl.py
└── README.md
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/SachinGarg-hub/URLScope
cd URLScope
```

### Create Virtual Environment

Windows:

```bash
python -m venv venv
venv\Scripts\activate
```

Linux / Mac:

```bash
python3 -m venv venv
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Train Model

```bash
python train_model.py --csv "data/dataset_with_all_features v2.csv"
```

This trains all five base models plus the F1-weighted Voting Ensemble, applies the root-domain augmentation described above, and saves the result to `models/urlscope_model.joblib`.

**After every retrain, verify before trusting it:**

```bash
python sanity_check.py
```

If any check fails, use `explain_prediction.py "<url>"` to see which feature is driving the wrong score, and `diagnose_dataset.py "<csv path>"` to check whether the underlying data has a class-wise structural bias.

---

## Run Application

```bash
streamlit run app.py
```

---

## Workflow

1. User enters a URL
2. Feature extractor processes the URL (canonical, scheme-independent form)
3. ML ensemble evaluates phishing probability
4. Domain-reputation allowlist caps the score for recognized institutions
5. SHAP explains feature importance
6. Risk verdict is displayed

---

## Performance Metrics

Models are evaluated using Accuracy, Precision, Recall, F1, and ROC-AUC. Latest results after root-domain augmentation (769k rows, 557k safe / 212k phishing):

| Model | Accuracy | Precision | Recall | F1 | ROC-AUC |
|---|---|---|---|---|---|
| Decision Tree | 0.8278 | 0.6959 | 0.6659 | 0.6805 | 0.8518 |
| Random Tree | 0.6141 | 0.4014 | 0.8147 | 0.5378 | 0.7318 |
| Logistic Regression | 0.7982 | 0.6406 | 0.6097 | 0.6248 | 0.8216 |
| Random Forest | 0.8692 | 0.7647 | 0.7586 | 0.7617 | 0.9164 |
| XGBoost | 0.8478 | 0.7082 | 0.7611 | 0.7337 | 0.9065 |
| **Voting Ensemble (deployed)** | 0.8439 | 0.7051 | 0.7454 | 0.7247 | 0.8933 |

> These numbers are on the augmented dataset's held-out split. The more meaningful validation, given the dataset issues documented above, is `sanity_check.py` against real-world URLs rather than held-out accuracy alone — a model can score well on a held-out split from a biased dataset while still failing badly in production.

---

## Future Scope

* Expand and/or externalize the domain-reputation allowlist (e.g. pull from a maintained public list rather than a hardcoded set)
* Browser extension support
* Real-time threat intelligence API integration
* Deep learning models
* Live WHOIS/SSL integration made the default rather than optional
* Enterprise dashboard
* Chrome extension deployment

---

## Applications

* Cybersecurity systems
* Threat intelligence
* Browser security tools
* Educational research
* Enterprise phishing defense

---

## Conclusion

URLScope provides a reliable and explainable solution for phishing detection using machine learning, combined with a domain-reputation layer to cover the cases pure lexical ML can't reliably resolve on its own. By combining multiple feature categories, class-imbalance-aware training, dataset-bias diagnostics, a performance-weighted ensemble, and explainable AI, the platform helps users identify malicious websites before becoming victims of cyber attacks.

---

## Contributors

* Sachin Garg
* Goutam
* Navdeep
* Arsh Kambooj
* Arnavdeep

---

## License

This project is licensed under the MIT License.
