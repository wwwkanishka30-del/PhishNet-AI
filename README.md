# PhishNet AI - Machine Learning Model Documentation

## 1. Overview
This directory contains the serialized machine learning artifacts, evaluation metrics, and feature configurations for PhishNet AI's optional supervised classification pipeline.

The model acts as an analytical extension alongside the primary rule-based heuristic engine, providing a hybrid defense-in-depth approach for URL categorization.

---

## 2. Dataset Specification
- **Dataset File**: `data/dataset.csv`
- **Total Samples**: 100 benchmark URLs
  - 50 Legitimate URLs (sampled from Tranco/Alexa top domains, academic portals, and official APIs)
  - 50 Phishing / Malicious URLs (curated patterns representing PhishTank, OpenPhish, and observed credential harvesting campaigns)
- **Class Balance**: 50% Legitimate (`0`), 50% Phishing (`1`)
- **Data Splitting**: Stratified 80/20 train/test split (`random_state=42`)
  - Training Set: 80 samples (40 Legitimate, 40 Phishing)
  - Testing Set: 20 samples (10 Legitimate, 10 Phishing)
- **Data Leakage Safeguards**: Feature extraction is computed independently on individual URL strings without global state or label contamination.

---

## 3. Extracted Feature Vector (12 Features)
The pipeline converts each raw URL into a 12-dimensional numerical vector:

| Index | Feature Name | Description | Type |
|---|---|---|---|
| 0 | `url_length` | Total character count of normalized URL | Integer |
| 1 | `hostname_length` | Length of authority/hostname portion | Integer |
| 2 | `dot_count_host` | Frequency of '.' in hostname | Integer |
| 3 | `hyphen_count_host` | Frequency of '-' in hostname | Integer |
| 4 | `has_at_symbol` | Presence of userinfo '@' symbol | Binary (0/1) |
| 5 | `is_ip_host` | Direct IPv4/IPv6 address as host | Binary (0/1) |
| 6 | `is_https` | HTTPS protocol enabled | Binary (0/1) |
| 7 | `subdomain_count` | Number of subdomain hierarchy levels | Integer |
| 8 | `path_length` | Total character count of path | Integer |
| 9 | `query_length` | Total character count of query parameters | Integer |
| 10 | `has_suspicious_keyword` | Presence of sensitive credentials/action keywords | Binary (0/1) |
| 11 | `has_target_brand` | Presence of high-profile target brand token | Binary (0/1) |

---

## 4. Models and Evaluation Results

### Model Architecture
- **Primary Model**: `RandomForestClassifier` (100 estimators, max depth 6, `random_state=42`)
- **Baseline Model**: `LogisticRegression` (`max_iter=1000`, `random_state=42`)

### Test Set Performance Metrics
- **Accuracy**: 100.0% (20 / 20 test samples correctly classified)
- **Precision**: 1.0000
- **Recall**: 1.0000
- **F1-Score**: 1.0000
- **Confusion Matrix**:
  - True Negatives (TN): 10
  - False Positives (FP): 0
  - False Negatives (FN): 0
  - True Positives (TP): 10

### Feature Importance Ranking (Random Forest)
1. `has_suspicious_keyword`: 0.2469
2. `url_length`: 0.2194
3. `hyphen_count_host`: 0.2099
4. `hostname_length`: 0.1023
5. `is_https`: 0.0966
6. `subdomain_count`: 0.0339
7. `is_ip_host`: 0.0278
8. `dot_count_host`: 0.0276
9. `has_target_brand`: 0.0172
10. `path_length`: 0.0158
11. `has_at_symbol`: 0.0019
12. `query_length`: 0.0007

---

## 5. Limitations and Disclaimers
1. **Curated Benchmark Size**: The bundled dataset comprises 100 illustrative and representative patterns designed for reproducible local training and portfolio demonstration. For production deployment at scale, training on millions of live feeds (e.g. APWG, PhishTank dumps) is recommended.
2. **Concept Drift**: Phishing tactics evolve rapidly (e.g., zero-day URL obfuscation, newly registered gTLDs). Static ML models require continuous periodic retraining.
3. **Defense-in-Depth**: PhishNet AI uses this ML model to augment—not replace—the deterministic rule-based explainability engine.
