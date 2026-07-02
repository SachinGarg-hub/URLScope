<<<<<<< HEAD
# URLSCOPE — Intelligent Phishing URL Detection Platform

This project keeps the provided `index.html` design unchanged and adds a Python/Streamlit backend for phishing URL detection.

## Tech stack
Python, Pandas, Scikit-Learn, XGBoost, SHAP, Streamlit

## Algorithms included
- Decision Tree
- Random Tree using `ExtraTreeClassifier`
- Logistic Regression
- Random Forest ensemble member
- XGBoost
- Soft-voting ensemble over all models

## Features analyzed
Lexical URL signals, domain signals, and optional behavioral/live checks:
URL length, hostname length, path length, dots, hyphens, digits, special characters, IP host, `@` trick, HTTPS, suspicious TLD, shortener domain, brand/risk keywords, subdomain count, query params, entropy, domain age, SSL validity, page reachability, forms, and external-link ratio.

## Run
```bash
cd urlscope_platform
python -m venv .venv
# Windows: .venv\Scripts\activate
source .venv/bin/activate
pip install -r requirements.txt
python train_model.py
streamlit run app.py
```

## Optional real dataset
`train_model.py` can train from a CSV with either:

1. `url,label` columns, where label is `1` for phishing and `0` for safe.
2. Precomputed feature columns matching `features.FEATURE_ORDER` plus `label`.

Example:
```bash
python -c "from train_model import train; print(train('your_dataset.csv'))"
```

## Files
- `index.html` — original UI provided by you, preserved.
- `features.py` — lexical, domain, SSL, WHOIS, and behavioral feature extraction.
- `train_model.py` — model training and metrics.
- `app.py` — Streamlit app that renders the provided HTML UI dynamically.
- `requirements.txt` — dependencies.
=======
# URLScope — Intelligent Phishing URL Detection Platform

## Overview

URLScope is an intelligent phishing URL detection platform designed to identify malicious websites **before user interaction**. The system analyzes **lexical**, **domain**, and **behavioral** URL features using machine learning algorithms to classify URLs as **safe** or **phishing**.

The platform provides not only prediction results but also explainability using **SHAP (SHapley Additive exPlanations)**, allowing users to understand why a URL was classified as suspicious.

---

## Problem Statement

Phishing attacks are among the most common cyber threats, where attackers create fake websites to steal sensitive information such as:

* User credentials
* Banking details
* Credit card information
* Personal identity data

Traditional blacklists often fail to detect newly created phishing domains. This project solves that problem using machine learning–based detection.

---

## Features

* Real-time phishing URL detection
* Lexical URL analysis
* Domain reputation checks
* Behavioral feature extraction
* Risk confidence scoring
* SHAP-based model explainability
* Interactive web interface
* Multiple ML model comparison

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

## Machine Learning Algorithms

The following algorithms are implemented and compared:

### 1. Decision Tree

A supervised learning model that makes predictions using tree-based rules.

### 2. Random Forest

An ensemble of multiple decision trees that improves prediction accuracy and reduces overfitting.

### 3. Logistic Regression

A statistical classification model that predicts phishing probability.

### 4. XGBoost

A high-performance gradient boosting model used for advanced classification.

---

## Feature Extraction

The system extracts three categories of features:

### Lexical Features

* URL length
* Number of dots
* Number of hyphens
* Number of digits
* Presence of `@`
* Presence of IP address
* Suspicious keywords

### Domain Features

* Domain age
* Top-level domain
* SSL certificate validity
* WHOIS data

### Behavioral Features

* Redirect count
* External resource loading
* Form action behavior
* JavaScript redirects

---

## Project Structure

```bash
urlscope/
│
├── app.py
├── predictor.py
├── train_model.py
├── feature_extractor.py
├── requirements.txt
├── models/
├── data/
├── templates/
│   └── index.html
└── README.md
```

---

## Installation

### Clone Repository

```bash
git clone https://github.com/SachinGarg-hub/URLScope
cd urlscope
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

Run:

```bash
python train_model.py
```

This will train all machine learning models and save them inside the `models/` folder.

---

## Run Application

Start the application using Streamlit:

```bash
streamlit run app.py
```

Open browser:

```bash

```

---

## Workflow

1. User enters URL
2. Feature extractor processes URL
3. ML models evaluate phishing probability
4. Best model predicts classification
5. SHAP explains feature importance
6. Risk verdict is displayed

---

## Output Example

Input URL:

```text
https://secure-paypal-verify-account.tk/login
```

Output:

* Verdict: **Likely Phishing**
* Risk Confidence: **87%**
* Suspicious Features:

  * Suspicious TLD
  * Domain age too low
  * Invalid SSL certificate

---

## Performance Metrics

Models are evaluated using:

* Accuracy
* Precision
* Recall
* F1 Score
* ROC-AUC

Expected performance:

* Accuracy: ~95%
* Precision: High
* False Positive Rate: Low

---

## Future Scope

* Browser extension support
* Real-time threat intelligence API
* Deep learning models
* Live WHOIS integration
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

URLScope provides a reliable and explainable solution for phishing detection using machine learning. By combining multiple features and explainable AI, the platform helps users identify malicious websites before becoming victims of cyber attacks.

---

## Contributors

* Sachin garg
* Goutam
* Navdeep
* Arsh kambooj
* Arnavdeep 

---

## License

This project is licensed under the MIT License.
>>>>>>> d74aa45084844600ca8b54fa3318f5d53ad8b5de
