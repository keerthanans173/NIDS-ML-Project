# SentinelFlow NIDS — Upgrade Changelog

All notable changes made during the modernization of the Network Intrusion Detection System project are documented here.

---

## [Version 2.4.0] — SentinelFlow Modernization

### 1. Kept & Preserved (Backward Compatibility)
* **Core Stack**: Flask backend, SQLite database persistence, and NSL-KDD benchmark datasets (`data/KDDTrain+.txt`, `data/KDDTest+.txt`).
* **Fallback Model**: Legacy `ids_model.pkl` is preserved and configured as an automatic fallback if primary pipeline deserialization ever fails.
* **Preserved Route Endpoints**:
  * `GET /`: Renders detection studio (manual form preserved with all 41 KDD features).
  * `POST /predict`: Handles incoming telemetry forms and JSON requests, persists to `predictions` table, and returns `result.html` (or JSON if requested).
  * `GET /history`: Lists prediction history audit logs.
  * `POST /clear_history`: Purges historical telemetry and redirects to `/history`.
  * `GET /dashboard`: Analytics dashboard overview.
  * `GET /about`: Architecture, NSL-KDD background, and author contact.

---

### 2. Restructured (Backend Architecture)
* **Application Factory**: Moved monolithic `app.py` into `app/__init__.py` using Flask's application factory pattern (`create_app()`).
* **Modular Blueprints** (`app/routes/`):
  * `auth.py`: Session management, RBAC (`Admin`, `Analyst`, `Viewer`), password hashing, and instant demo role switcher.
  * `detect.py`: Multi-modal detection studio (Manual Form, CSV Batch Ingestion, Live Replay Stream, Experimental Packet Capture).
  * `dashboard.py`: Real-time KPI aggregation, temporal timeline spikes, and attack vector donut distributions.
  * `alerts.py`: Incident triage workflow, analyst notes, SHAP feature waterfalls, and simulated IP block mitigation.
  * `models.py`: Model Lab test-set metrics, confusion matrix, ROC curves, feature importances, and background retraining.
  * `reports.py`: PDF report generation (ReportLab), CSV data export, attack simulator, history audit log, and system settings.
* **Enterprise Services** (`app/services/`):
  * `detector.py`: Thread-safe singleton for model inference, dynamic sensitivity thresholding, and risk scoring.
  * `explainer.py`: SHAP TreeExplainer integration computing top 5 contributing features per prediction and translating them into plain-English sentences.
  * `simulator.py`: Background replay streamer emitting real-time events over Flask-SocketIO at 1x, 5x, 10x speeds, plus synthetic attack burst injection.
  * `report.py`: Automated executive PDF dossier generation using ReportLab.
* **Database Models** (`app/models/` via Flask-SQLAlchemy):
  * `User`: Credentials, password hash, role (`Admin`, `Analyst`, `Viewer`).
  * `Prediction`: Full 41-feature telemetry fields, attack classification, confidence, risk score, and analyst status.
  * `Alert`: Incident tracking, severity level, plain-English explanation, top SHAP features JSON.
  * `BlockedIP`: Simulated firewall mitigations, expiration timestamp, generated `iptables` and Windows `netsh` commands.
  * `AuditLog`: Action audit trail for SOC operators.
  * `SystemSetting`: Persistent runtime configuration.

---

### 3. ML Pipeline & Model Upgrades
* **Unified Pipeline** (`app/ml/preprocess.py`): Encapsulates categorical encoders, StandardScaler, and target label encoder inside `SentinelDataPipeline` saved in `sentinel_pipeline.joblib` to prevent training-serving drift.
* **Model Benchmark & Comparison** (`app/ml/train.py`):
  * Trained and compared Random Forest, XGBoost, and Isolation Forest anomaly boundaries.
  * XGBoost selected as best classifier based on macro-F1 score (0.6073 macro-F1, 78.93% test accuracy on full 22,544 rows of `KDDTest+`).
  * Addressed class imbalance for rare attacks (`U2R`, `R2L`) via balanced resample thresholds and balanced loss functions.
* **Honest Test-Set Evaluation** (`app/ml/evaluate.py` -> `app/ml/metrics.json`):
  * All accuracy and F1 metrics displayed in the UI are computed directly from the real test set (`KDDTest+`).
  * Multi-class ROC curves and normalized confusion matrix heatmaps rendered directly from serialized evaluation metrics.
* **Explainability**: Integrated SHAP TreeExplainer with background sample distribution to compute local feature attributions for every prediction.

---

### 4. UI & Modern Light Theme Design
* **Design System**: Replaced dark neon cyberpunk theme with an elegant warm light theme:
  * Background: Warm Cream (`#FFF8F0`)
  * Surface: Pure White (`#FFFFFF`)
  * Panels: Soft Cream (`#FFEFD9`)
  * Brand Accents: Warm Orange (`#F97316`) and Amber (`#FBBF24`)
  * Danger / Critical: Deep Red (`#DC2626`)
  * Typography: Display headings in `Fraunces` serif display with `Inter` body text.
* **Sidebar Layout**: Modern left navigation bar with active state pills, real-time radar sweep monitoring animation, and role switcher.
* **Live Updates**: Flask-SocketIO streaming packet telemetry and instant toast alerts on high-severity detections.

---

### 5. Deployment & Quality
* **Tests**: Full automated `pytest` test suite covering preprocessing, detector risk calculations, SHAP outputs, and Flask API routes.
* **Deployment Assets**: Production `Dockerfile`, pinned `requirements.txt`, environment template `.env.example`, `.gitignore`, and `Procfile`.
