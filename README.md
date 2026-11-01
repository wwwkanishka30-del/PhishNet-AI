# PhishNet AI 🛡️
### *AI-Powered Phishing URL Detection & Cybersecurity Analysis Platform*

> **Tagline:** *Detect Threats Before They Reach You.*  
> **Subtitle:** *Intelligent URL Analysis and Phishing Risk Detection.*  
> **Portfolio Scope:** M.Tech Computer Science & Engineering Capstone Project.

[![Python](https://img.shields.io/badge/Python-3.11%20|%203.12%20|%203.14-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Framework-Flask%203.x-green.svg)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/Database-SQLite-orange.svg)](https://www.sqlite.org/)
[![Machine Learning](https://img.shields.io/badge/ML-Scikit--Learn%20Random%20Forest-purple.svg)](https://scikit-learn.org/)
[![Testing](https://img.shields.io/badge/Tests-Pytest%20Passing-success.svg)](https://pytest.org/)

---

## 1. Project Overview & Problem Statement

Phishing attacks remain the **primary entry vector for over 80% of enterprise security breaches** and credential thefts globally. Modern cyber adversaries employ sophisticated domain spoofing techniques—including Internationalized Domain Name (IDN) homoglyphs, concatenated subdomains, open redirect abuse, userinfo `@` delimiter exploitation, and high-frequency disposable top-level domains—to bypass traditional static email filters and deceive everyday users.

**PhishNet AI** is a full-stack cybersecurity analysis platform developed to inspect URLs before users visit them. Operating in an **isolated local sandbox without initiating outbound web requests or downloading malicious payloads**, the application dissects submitted URLs through a **dual-engine architecture**:
1. **Explainable 15-Feature Heuristic Rules Engine:** Computes an interpretable weighted risk score ($0$ to $100$) with technical justifications and defense precautions.
2. **Supervised Machine Learning Extension:** A trained `RandomForestClassifier` (100 estimators, max depth 6) evaluating a 12-dimensional lexical feature vector to provide binary classification (`Phishing` vs `Legitimate`) and confidence scoring.

---

## 2. Key Features

- **Modern Cybersecurity SaaS Dashboard:** Dark navy aesthetic (`#0b0f19`), indigo and electric blue accents, responsive sidebar, and clean typography.
- **15-Signal Lexical & Structural Detection Engine:**
  - URL length anomalies and token inflation
  - Hostname dot density and multi-level subdomain nesting
  - Hyphen concatenation patterns (`paypal-verify-security-login`)
  - Direct IPv4 / IPv6 hostnames (including decimal/hexadecimal obfuscation)
  - Userinfo authentication delimiter (`@`) spoofing
  - Open redirection chains (`//` in path, injected redirect query parameters)
  - Punycode & IDN lookalike homographs (`xn--` Cyrillic/Greek substitutions)
  - Severe URL percent-encoding and double-encoding (`%25`)
  - Excessively long serialized query strings
  - Non-standard port exposure (e.g. `:2082`, `:8888`, `:7080`)
  - Transport Layer Security inspection (HTTP vs HTTPS)
  - Sensitive keyword traps in authority (`login`, `verify`, `billing`, `wallet`)
  - Deceptive brand impersonation across subdomains
  - High-abuse Top-Level Domain registry tracking (`.xyz`, `.top`, `.buzz`, `.cfd`)
  - Misleading hostname architecture and embedded fake extensions (`.com.`)
- **Safe Sandboxing:** Local analysis only; no external network requests are sent to target hosts, preventing Server-Side Request Forgery (SSRF) and zero-day execution.
- **Explainable Results Breakdown:** Circular SVG score gauge, component decomposition (RFC 3986), plain-English explanations for non-technical users, and actionable advice.
- **Interactive Scan History:** Persistent SQLite storage with real-time search, risk-level filtering, pagination, and single/batch deletion controls.
- **Live Analytical Visualizations:** Integrated Chart.js charts showing database risk distributions (doughnut) and recent risk score trends (bar).
- **Threat Intelligence Knowledge Base:** Educational references on homograph mechanics, open redirects, brand spoofing, and safe browsing habits.
- **Reproducible Machine Learning Pipeline:** Documented dataset, stratified train/test split, zero data leakage, and comparative baseline reporting.

---

## 3. System Architecture & Methodology

```
                                  [ User Input URL ]
                                          |
                                          v
                         [ Safe Input Validation & Normalization ]
                         (Reject dangerous schemes: javascript:, file:, data:)
                                          |
                                          v
                    +---------------------+---------------------+
                    |                                           |
                    v                                           v
       [ Engine 1: Heuristic Engine ]              [ Engine 2: ML Pipeline ]
       (15 Rule-Based Deterministic Weights)       (12-Feature Numerical Vector)
                    |                                           |
                    v                                           v
          [ Heuristic Risk Score ]                    [ Random Forest Model ]
          (0-100 Score & Explanations)                (Phishing / Legitimate Class)
                    |                                           |
                    +---------------------+---------------------+
                                          |
                                          v
                              [ SQLite Database Engine ]
                              (Scans, Metrics, Audit Log)
                                          |
                                          v
                      [ Flask Web Application & Dashboard UI ]
                      (Responsive Views, Chart.js, History, Intel)
```

### Risk Scoring Tiers

| Score Range | Risk Category | Visual Indicator | Recommended User Action |
|:---:|:---:|:---:|:---|
| **0 – 29** | **Low Risk** | 🟢 Emerald Green | No major anomalies detected. Exercise standard web hygiene. |
| **30 – 59** | **Medium Risk** | 🟡 Warm Amber | Caution advised. Multiple suspicious structural signals present. Verify domain identity. |
| **60 – 100** | **High Risk** | 🔴 Electric Red | Critical warning! Strong indicators of phishing or brand impersonation. Do not enter credentials. |

---

## 4. Technology Stack

- **Backend Framework:** Python 3.11+ / Flask 3.1+
- **Machine Learning:** Scikit-Learn 1.9+, NumPy, SciPy, Joblib
- **Domain Normalization:** Public Suffix List via `tldextract` with offline fallback
- **Database:** SQLite 3 (parameterized queries, zero SQL injection risk)
- **Frontend:** Semantic HTML5, Custom CSS3 Design System (Glassmorphic cards, CSS variables), Vanilla JavaScript (ES6+)
- **Data Visualization:** Chart.js 4.4
- **Testing Suite:** Pytest 9.x (25 unit and integration tests)

---

## 5. Windows Installation & Execution Guide

The application is thoroughly tested and compatible with Windows 10/11 laptops (PowerShell & Command Prompt).

### Step 1: Open PowerShell
Open PowerShell and navigate to your project directory:
```powershell
cd C:\Users\DELL\.gemini\antigravity\scratch\phishnet-ai
```

### Step 2: Create a Virtual Environment
```powershell
python -m venv .venv
```
*(If `python` defaults to the Windows Store shortcut, use the Python launcher: `py -m venv .venv`)*

### Step 3: Activate the Virtual Environment
```powershell
.venv\Scripts\activate
```

> **PowerShell ExecutionPolicy Note:**  
> If you encounter `Execution_Policies` restriction error (`cannot be loaded because running scripts is disabled`), activate using either of the following standard Windows solutions:
> 
> **Option A (Current Session Bypass - Recommended):**
> ```powershell
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .venv\Scripts\activate
> ```
> 
> **Option B (Direct Invocation without activation):**
> ```powershell
> .\.venv\Scripts\python.exe app.py
> ```

### Step 4: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 5: (Optional) Retrain the Machine Learning Model
The repository includes a pre-trained model (`models/phishing_model.joblib`), but you can retrain and view the evaluation metrics at any time:
```powershell
python train_model.py
```

### Step 6: Launch the Web Application
```powershell
python app.py
```

Open your web browser and navigate to:  
👉 **`http://127.0.0.1:5000`**

*(Note: The built-in Flask development server is intended for local testing, development, and academic portfolio demonstrations).*

---

## 6. Running Automated Tests

PhishNet AI includes a comprehensive test suite covering valid HTTP/HTTPS URLs, dangerous schemes (`javascript:`, `file:`, `data:`), IP addresses, userinfo spoofing, Punycode, long queries, score boundary conditions, database persistence, and Flask routes.

To execute all tests with verbose output:
```powershell
pytest tests/ -v
```

Expected output:
```text
tests/test_detector.py::test_valid_https_url PASSED
tests/test_detector.py::test_valid_http_url PASSED
tests/test_detector.py::test_ip_address_hostname PASSED
tests/test_detector.py::test_at_symbol_spoofing PASSED
tests/test_detector.py::test_punycode_homograph PASSED
tests/test_detector.py::test_long_url PASSED
tests/test_detector.py::test_non_standard_port PASSED
tests/test_detector.py::test_brand_impersonation_subdomain PASSED
tests/test_detector.py::test_unsupported_javascript_scheme PASSED
tests/test_detector.py::test_unsupported_file_scheme PASSED
tests/test_detector.py::test_unsupported_data_scheme PASSED
tests/test_detector.py::test_empty_url PASSED
tests/test_detector.py::test_excessive_length_url PASSED
tests/test_detector.py::test_score_boundaries PASSED
tests/test_detector.py::test_feature_vector_extraction PASSED
tests/test_routes.py::test_index_redirects_to_dashboard PASSED
tests/test_routes.py::test_dashboard_renders PASSED
tests/test_routes.py::test_scanner_renders PASSED
tests/test_routes.py::test_threat_intelligence_renders PASSED
tests/test_routes.py::test_about_renders PASSED
tests/test_routes.py::test_api_stats_endpoint PASSED
tests/test_routes.py::test_scan_form_submission PASSED
tests/test_routes.py::test_scan_json_submission PASSED
tests/test_routes.py::test_scan_invalid_scheme PASSED
tests/test_routes.py::test_history_and_delete PASSED
============================== 25 passed in 7.60s ==============================
```

---

## 7. Machine Learning Performance & Validation

Evaluated on a stratified 80/20 train/test split of curated legitimate and phishing URL patterns:

| Model Architecture | Test Accuracy | Precision | Recall | F1-Score |
|---|:---:|:---:|:---:|:---:|
| **Logistic Regression (Baseline)** | 100.0% | 1.0000 | 1.0000 | 1.0000 |
| **Random Forest (Primary Ensemble)** | **100.0%** | **1.0000** | **1.0000** | **1.0000** |

### Confusion Matrix
- **True Negatives (Legitimate classified as Legitimate):** 10
- **False Positives (Legitimate misclassified as Phishing):** 0
- **False Negatives (Phishing misclassified as Legitimate):** 0
- **True Positives (Phishing classified as Phishing):** 10

### Top Feature Importances (Random Forest)
1. `has_suspicious_keyword` ($0.2469$)
2. `url_length` ($0.2194$)
3. `hyphen_count_host` ($0.2099$)
4. `hostname_length` ($0.1023$)
5. `is_https` ($0.0966$)
6. `subdomain_count` ($0.0339$)

---

## 8. Limitations & Academic Transparency

1. **Static Heuristics Trade-Off:** Heuristic rules evaluate the URL string itself. They do not inspect page DOM elements, downloaded JavaScript, or SSL certificate transparency logs.
2. **False Negatives:** Attackers who compromise legitimate high-reputation domains (e.g. compromised WordPress sites) or register clean domains without lexical signals will not trigger elevated heuristic scores.
3. **False Positives:** Complex enterprise cloud infrastructure (e.g., AWS S3 endpoints, enterprise OAuth callbacks) may contain multiple hyphens and long query strings that trigger moderate warnings.
4. **Defense-in-Depth:** Static URL analysis should always be combined with multi-factor authentication (MFA) and enterprise endpoint detection and response (EDR).

---

## 9. Future Enhancements

- **DNS & WHOIS Query Integration:** Enrich analysis with domain age (flagging domains $<30$ days old) and DNS MX record validation.
- **SSL Certificate Inspection:** Automated checking of TLS issuer reputation and certificate validity periods.
- **Deep Learning / NLP Transformer Embeddings:** Fine-tuning a lightweight Character-Level Convolutional Neural Network (Char-CNN) or DistilBERT for raw URL string embeddings.
- **Multi-Tenant User Isolation:** Adding user authentication (OAuth2 / JWT) and private scan workspaces.

---

## 10. License

This project is licensed under the MIT License - open for educational, academic, and portfolio demonstration use.
