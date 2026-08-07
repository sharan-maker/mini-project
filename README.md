# AI-Based Website Threat Detection Using SSL/TLS and Machine Learning

## Overview

AI-Based Website Threat Detection is a cybersecurity web application that analyzes websites and predicts whether they are **Safe**, **Suspicious**, or **Malicious**. Unlike traditional security tools that rely only on blacklists or SSL certificates, this project combines **SSL/TLS certificate analysis**, **website security features**, and **Machine Learning** to provide an intelligent threat assessment.

The system accepts a website URL from the user, extracts various security-related features, processes them using a trained machine learning model, and generates a detailed security report with a threat score and explanation.

---

# Problem Statement

Many users believe that a website with HTTPS is automatically safe. However, attackers can also obtain valid SSL/TLS certificates for phishing or malicious websites. Therefore, SSL alone cannot determine whether a website is trustworthy.

This project addresses this limitation by combining SSL certificate analysis with multiple security indicators and AI-based classification to improve website threat detection.

---

# Objectives

* Detect malicious or phishing websites using Machine Learning.
* Analyze SSL/TLS certificates for security-related information.
* Extract website security features automatically.
* Generate an overall website risk score.
* Explain why a website is considered safe or risky.
* Provide an easy-to-use web interface for users.

---

# Key Features

* Website URL Analysis
* SSL/TLS Certificate Inspection
* Domain Information Analysis (WHOIS)
* HTTP Security Header Analysis
* URL Structure Analysis
* Machine Learning Threat Prediction (Random Forest)
* Explainable AI Results
* Threat Score Dashboard

---

# System Workflow

```
User

   │

Enter Website URL

   │

────────────────────────────

Feature Extraction Module

────────────────────────────

SSL Certificate

Domain Information (WHOIS)

HTTP Headers

URL Features

DNS Information

   │

────────────────────────────

Machine Learning Model

(Random Forest)

   │

Threat Prediction

   │

Security Dashboard

Safe ✅

Suspicious ⚠️

Malicious ❌
```

---

# SSL/TLS Certificate Analysis

SSL/TLS is the core component of the project. Instead of simply checking whether HTTPS exists, the application extracts several certificate features.

## Certificate Issuer

Checks which Certificate Authority issued the SSL certificate.

Examples:

* DigiCert
* Google Trust Services
* Let's Encrypt
* Cloudflare

Trusted certificate authorities generally increase confidence, while unknown or suspicious issuers may increase risk.

---

## Certificate Validity

The application checks

* Issue Date
* Expiration Date

Certificates that are expired or close to expiration may indicate poor security practices.

---

## Certificate Age

Recently issued certificates can sometimes indicate newly created phishing websites.

Older certificates generally suggest a more established website.

---

## Self-Signed Certificate Detection

Self-signed certificates are not verified by trusted Certificate Authorities.

If detected, the website receives a higher risk score. (Treated as one signal among several, since legitimate internal/dev sites can also use self-signed certs.)

---

## TLS Version

Supported versions include

* TLS 1.3
* TLS 1.2

Older versions such as TLS 1.0 or TLS 1.1 are considered insecure and increase the website's risk level.

---

## Signature Algorithm

Examples

* SHA-256
* SHA-384

Older algorithms such as SHA-1 are considered weak.

---

## Cipher Suite

The project checks whether the website uses secure encryption algorithms.

Weak cipher suites increase the risk score.

---

## Certificate Revocation Status

The application verifies whether the SSL certificate has been revoked.

A revoked certificate is considered highly suspicious.

---

# URL Feature Extraction

The URL itself provides valuable information about website legitimacy.

Features include

* URL Length
* Number of Special Characters
* Number of Dots
* Presence of IP Address
* HTTPS Availability
* Suspicious Keywords
* Number of Subdomains

Example

```
https://google.com

Safe

---------------------------------

https://google-login-security-update123.com

Suspicious
```

---

# Domain Information Analysis

The system collects domain-related information such as

* Domain Age
* Domain Expiration Date
* Registrar
* Country
* WHOIS Information

Recently registered domains are generally considered more suspicious than older domains.

---

# HTTP Security Header Analysis

The application checks important HTTP security headers including

* Strict-Transport-Security (HSTS)
* Content-Security-Policy (CSP)
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy

Missing security headers may indicate poor website security.

---

# DNS Analysis

The project also analyzes basic DNS-related information such as

* DNS Records
* Name Servers
* IP Resolution

DNS anomalies can contribute to the overall threat score.

---

# Feature Engineering

All extracted features are converted into numerical values suitable for Machine Learning.

Example Features

* SSL Available
* Certificate Age
* Domain Age
* URL Length
* HTTPS Enabled
* Number of Subdomains
* Missing Security Headers
* TLS Version
* Certificate Authority
* Cipher Strength

These features become the input to the AI model.

---

# Machine Learning Model

The project uses supervised machine learning to classify websites.

**Algorithm: Random Forest**

Random Forest is used as the primary and only production model because it performs well on structured security datasets, is robust to noisy features, and provides feature importance for explainable predictions. Other algorithms (e.g., Logistic Regression) may be evaluated during experimentation for comparison in the project report, but only Random Forest is deployed in the final pipeline.

---

# Threat Classification

The model predicts one of three categories, based on a documented threat-score threshold:

| Threat Score | Classification |
|---|---|
| 0 – 30 | Safe ✅ |
| 31 – 65 | Suspicious ⚠️ |
| 66 – 100 | Malicious ❌ |

*(Exact thresholds to be tuned during model evaluation; documented here for reproducibility.)*

## Safe

The website follows recommended security practices and shows no major indicators of malicious activity.

## Suspicious

The website contains several warning signs that require caution.

Examples

* Newly registered domain
* Missing HTTP security headers
* Weak TLS configuration

## Malicious

The website exhibits multiple indicators commonly associated with phishing or malware.

Examples

* Self-signed certificate
* Expired certificate
* Suspicious URL
* Multiple security issues

---

# Explainable AI

Instead of displaying only the prediction, the system explains why the website received its score, using Random Forest feature importances.

Example

```
Threat Score : 82%

Reasons

• Domain created 5 days ago
• Self-signed SSL certificate
• Missing HSTS header
• URL contains suspicious keywords
• Weak TLS version
```

This makes the prediction transparent and easier for users to understand.

---

# Dataset & Evaluation

* Labeled data will be assembled from public phishing sources (e.g., PhishTank, OpenPhish) for malicious/suspicious examples and top-ranked domain lists (e.g., Tranco) for safe examples.
* SSL, WHOIS, DNS, and header features are extracted live for each domain rather than relying solely on pre-existing lexical-URL datasets.
* Extracted features are cached (database-backed) to avoid repeated live lookups and to keep demos reliable.
* Model performance is reported using train/test split with Accuracy, Precision, Recall, F1-score, and a confusion matrix.

---

# Technology Stack

## Frontend

* React.js
* HTML
* CSS
* JavaScript

## Backend

* FastAPI
* Python

## Machine Learning

* Scikit-learn (Random Forest)
* Pandas
* NumPy

## Security Libraries

* ssl
* OpenSSL
* cryptography
* requests
* python-whois
* tldextract
* BeautifulSoup

## Database

* PostgreSQL

## Deployment

* Docker
* GitHub
* Render / Railway

---

# Project Structure

```
AI-Website-Threat-Detection/

│

├── frontend/

│     ├── React Application

│

├── backend/

│     ├── API

│     ├── SSL Analyzer

│     ├── URL Analyzer

│     ├── Header Analyzer

│     ├── WHOIS Module

│     ├── DNS Module

│     ├── Feature Extractor

│     ├── Cache Layer

│     ├── AI Model

│

├── dataset/

│

├── models/

│

├── notebooks/

│

├── screenshots/

│

├── README.md

│

└── requirements.txt
```

---

# Expected Output

```
Website Security Report

Website:
https://example.com

Overall Risk

Safe ✅

Threat Score

12%

SSL Certificate

Valid

TLS Version

TLS 1.3

Domain Age

8 Years

Security Headers

Present

Prediction

Safe
```

---

# Future Enhancements

*(Deliberately out of scope for the core project — listed here as possible extensions only)*

* Browser Extension for real-time website scanning.
* Integration with Google Safe Browsing and PhishTank as a live signal source.
* Website screenshot analysis using Deep Learning.
* Malware URL detection using Deep Neural Networks.
* Continuous model retraining with newly discovered phishing websites.
* User authentication and scan history dashboard.
* API service for third-party applications.

---

# Conclusion

This project demonstrates how Artificial Intelligence can improve website security by combining SSL/TLS certificate analysis with URL, domain, DNS, and HTTP security features. Instead of relying solely on HTTPS, the system evaluates multiple indicators to provide a more accurate assessment of website safety. The inclusion of Explainable AI allows users to understand the reasons behind each prediction, making the solution both effective and transparent. This project is suitable as a final-year engineering project because it integrates cybersecurity, machine learning, backend development, and modern web technologies into a practical, well-scoped, real-world application.