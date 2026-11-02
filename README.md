# 🛡️ SentinelFlow NIDS — Explainable Network Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.12-F97316.svg?logo=python&logoColor=white)](https://python.org)
[![Framework](https://img.shields.io/badge/Flask-3.1.2-3B2F2A.svg?logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![ML](https://img.shields.io/badge/XGBoost-3.4.1-FBBF24.svg)](https://xgboost.readthedocs.io/)
[![Explainability](https://img.shields.io/badge/SHAP-TreeExplainer-DC2626.svg)](https://shap.readthedocs.io/)
[![License](https://img.shields.io/badge/License-MIT-8A7568.svg)](LICENSE)

SentinelFlow is a modern, high-fidelity, explainable **Network Intrusion Detection System (NIDS)** built on Flask, XGBoost, and SHAP. It ingests network connection sessions, evaluates them across 41 dimensional traffic telemetry features from the NSL-KDD benchmark, computes calibrated risk scores (0–100), and translates feature importances into plain-English human sentences for security operations center (SOC) analysts.

---

## 🏛️ System Architecture

```text
 ┌────────────────────────────────────────────────────────────────────────┐
 │                    SENTINELFLOW NIDS ARCHITECTURE                      │
 └────────────────────────────────────────────────────────────────────────┘
                                    │
               ┌────────────────────┴────────────────────┐
               ▼                                         ▼
   [Live Replay Stream / CSV]                 [Manual Detection Studio]
         (KDDTest+ Records)                     (Grouped 41 Features)
               │                                         │
               └────────────────────┬────────────────────┘
                                    ▼
                     ┌─────────────────────────────┐
                     │ SentinelDataPipeline        │
                     │  - Categorical Encoders     │
                     │  - StandardScaler           │
                     │  - Unseen Class Protection  │
                     └──────────────┬──────────────┘
                                    ▼
       ┌────────────────────────────┴────────────────────────────┐
       ▼                                                         ▼
[XGBoost 5-Class Classifier]                          [Isolation Forest Anomaly]
 (Normal, DoS, Probe, R2L, U2R)                        (Contamination Boundary)
       │                                                         │
       └────────────────────────────┬────────────────────────────┘
                                    ▼
                     ┌─────────────────────────────┐
                     │ SentinelDetector Engine     │
                     │  - Multi-class Probs        │
                     │  - Dynamic Sensitivity      │
                     │  - Calibrated Risk (0-100)  │
                     └──────────────┬──────────────┘
                                    ▼
                     ┌─────────────────────────────┐
                     │ SHAP TreeExplainer          │
                     │  - Top 5 Feature Drivers    │
                     │  - Plain-English Synthesis  │
                     └──────────────┬──────────────┘
                                    ▼
       ┌────────────────────────────┴────────────────────────────┐
       ▼                                                         ▼
[Real-Time WebSocket Broadcast]                       [SQLite / PostgreSQL DB]
 (Socket.IO Traffic Ticker)                            (Predictions, Alerts, ACL)
       │                                                         │
       └────────────────────────────┬────────────────────────────┘
                                    ▼
           ┌─────────────────────────────────────────────────┐
           │        SentinelFlow Warm Light Dashboard        │
           │  (KPIs, Donut Charts, Triage, ReportLab PDF)   │
           └─────────────────────────────────────────────────┘
```

---

## 📊 Real Benchmark Metrics (NSL-KDD Test Set)

All metrics displayed in SentinelFlow are **empirically computed from the official `KDDTest+.txt` test set (22,544 rows)**. No fabricated accuracy values are used.

### Overall Performance Summary
| Metric | Random Forest | **XGBoost (Active Pipeline)** |
| :--- | :---: | :---: |
| **Accuracy** | 74.67% | **78.93%** |
| **Macro-F1 Score** | 0.5162 | **0.6073** |
| **Weighted-F1 Score** | 0.7020 | **0.7505** |
| **Macro-Precision** | 75.25% | **85.21%** |
| **Macro-Recall** | 50.60% | **58.41%** |
| **Multi-Class ROC-AUC** | 0.9340 | **0.9555** |
| **Training Latency** | 2.6s | **3.1s** |

### Per-Class Detailed Breakdown (XGBoost)
| Traffic Category | Precision | Recall | F1-Score | Test Support |
| :--- | :---: | :---: | :---: | :---: |
| **Normal** (Benign) | 96.5% | 83.6% | **0.8955** | 7,458 |
| **DoS** (Denial of Service) | 69.3% | 97.1% | **0.8088** | 9,711 |
| **Probe** (Reconnaissance) | 84.9% | 79.0% | **0.8187** | 2,421 |
| **R2L** (Remote to Local) | 98.1% | 7.0% | **0.1312** | 2,887 |
| **U2R** (User to Root) | 77.3% | 25.4% | **0.3820** | 67 |

> **Note on R2L / U2R Recall**: In NSL-KDD, the test set (`KDDTest+`) intentionally includes 17 novel zero-day attack types that never appeared in `KDDTrain+`. This reflects realistic intrusion conditions where unseen exploits have lower initial recall, as thoroughly documented in network security literature.

---

## 🚀 Key Features

1. **Multi-Modal Detection Studio**:
   * **Manual Form**: 41 grouped features (Basic, Content, Traffic rates) with tooltips, beginner/expert toggles, and prefilled presets (`Normal`, `DoS`, `Probe`, `R2L`, `U2R`).
   * **CSV Batch Ingestion**: Upload custom CSV telemetry with animated progress bar and downloadable results.
   * **Live Replay Stream**: Stream benchmark packets from `KDDTest+` at 1x, 5x, or 10x speeds via WebSocket.
   * **Experimental Packet Sniffing**: Reference guide and requirements for physical network interface capture.
2. **Explainable AI (XAI)**:
   * SHAP TreeExplainer computes exact marginal contributions per feature.
   * Synthesizes findings into natural English (e.g., *"Flagged as DoS primarily due to an elevated SYN error rate of 1.00 and high connection count (250) on destination private port"*).
3. **Automated Incident Response**:
   * Simulated IP blocklist with automated expiration windows.
   * Generates production-ready firewall commands for both Linux (`iptables`) and Windows (`netsh`).
4. **Interactive Attack Simulator**:
   * Stress-test the NIDS with synthetic burst injections of DoS, Probe, R2L, and U2R traffic with intensity controls (1–25 packets).
5. **Model Lab**:
   * Confusion matrix heatmaps, multi-class ROC curves, and global feature importance ranking.
   * "Retrain" button executes background model fitting and re-evaluates test-set metrics in real time.
6. **Executive PDF & CSV Reports**:
   * Automated executive PDF dossiers generated via ReportLab.
   * Raw CSV telemetry downloads for SIEM integration.
7. **Role-Based Access Control (RBAC)**:
   * Flask-Login integration with three distinct roles: `Admin`, `Analyst`, and `Viewer`. Includes quick demo switcher for evaluation.

---

## 🛠️ Installation & Setup

### 1. Clone & Enter Project Directory
```bash
git clone <repository-url>
cd "network intrusion project"
```

### 2. Create Virtual Environment
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/macOS:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment
```bash
cp .env.example .env
```

### 5. Train / Validate Pipeline
```bash
python app/ml/train.py
```

### 6. Run Application
```bash
python app.py
```
Visit `http://localhost:5000` in your web browser.

---

## 🧪 Automated Testing
Run the comprehensive test suite with `pytest`:
```bash
python -m pytest tests/
```

---

## ⚠️ Important Dataset Limitations & Disclaimer
1. **Synthesized Statistical Windows**: The NSL-KDD dataset represents connection records aggregated over 2-second historical sliding windows (e.g. `count`, `serror_rate`, `same_srv_rate`) rather than raw byte-level PCAP payloads.
2. **Legacy Protocol Signatures**: NSL-KDD benchmark traffic reflects legacy TCP/IP services and does not contain modern encrypted protocols (e.g., TLS 1.3, HTTP/3, QUIC).

---

## ⚖️ Legal & Ethical Notice
This software is intended strictly for educational, defensive research, and authorized auditing of computer networks. Deploying this system to capture or disrupt network traffic on infrastructure without explicit, written administrative consent is illegal under the Computer Fraud and Abuse Act (CFAA) and international cyber laws.
