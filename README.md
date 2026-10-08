# CyberLens — Institutional Threat Intelligence & Risk Assessment

<div align="center">
  <img src="frontend/logo.svg" alt="CyberLens Logo" width="320"/>
  <p><strong>Precision IOC Analysis & Deterministic Multi-Engine Threat Classification</strong></p>
</div>

---

## Overview

**CyberLens** is an institutional-grade Cyber Threat Intelligence (CTI) platform engineered for rapid triage, validation, and explainable risk assessment of Indicators of Compromise (IOCs). 

Designed with an aesthetic white/warm-cream editorial interface, CyberLens bridges external threat telemetry feeds (VirusTotal v3 and AbuseIPDB v2) into a unified, normalized data schema and applies a deterministic, explainable 0–100 risk scoring algorithm.

---

## Key Capabilities

* **Multi-Format Indicator Support**:
  * IPv4 & IPv6 Addresses (with automatic RFC 1918 private IP defense)
  * Domain Names (FQDN)
  * Web URLs (normalized via base64url encoding)
  * Cryptographic File Hashes (MD5, SHA-1, SHA-256)
* **Real-Time Input Hygiene & Defang Cleaner**:
  * Automatically strips defanged syntax (`hxxps://` $\to$ `https://`, `1[.]1[.]1[.]1` $\to$ `1.1.1.1`, `[:]` $\to$ `:`).
* **Multi-Source Asynchronous Ingestion**:
  * Concurrent querying of **VirusTotal API v3** and **AbuseIPDB API v2** via asynchronous HTTPX workers.
* **Explainable Risk Assessment Engine**:
  * Computes an auditable **0–100 Risk Score** mapped to standardized threat tiers: `LOW` (0–19), `MEDIUM` (20–49), `HIGH` (50–74), `CRITICAL` (75–100).
  * Automatically generates human-readable attribution justifications.
  * Vendor consensus scaling and severe threat override protection.
* **Persistent Audit Registry & JSON Reporting**:
  * SQLite persistence via SQLAlchemy.
  * Searchable historical investigation registry.
  * One-click downloadable JSON investigation dossiers.
* **100% Offline Capability**:
  * Bundled local Chart.js library (zero CDN reliance).
  * Discrete offline simulation mode toggled via `.env` (`OFFLINE_MODE=true`).

---

## Architecture

```
Client (Browser: HTML5 / CSS3 / Vanilla JS / Chart.js)
       │
       ▼ (REST / JSON)
FastAPI Application (Uvicorn / Pydantic / HTTPX)
  ├── 1. IOC Detection & Defang Sanitizer
  ├── 2. Strict Routability & SSRF Validation (RFC 1918 Guard)
  ├── 3. Asynchronous Provider Dispatcher (VT v3 + AbuseIPDB v2)
  ├── 4. Data Normalization Layer (UnifiedIOCReport)
  ├── 5. Explainable Risk Scoring Engine (YAML Rules)
  └── 6. Persistence & Report Generation (SQLite / SQLAlchemy)
```

---

## Quickstart

### 1. Prerequisites
* Python 3.10+ (tested with Python 3.14)
* Git

### 2. Installation
```bash
# Clone the repository
git clone https://github.com/Vyom-Repo/CyberLens.git
cd CyberLens

# Create and activate virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration
Copy `.env.example` to `.env` and insert your threat intelligence API keys:
```bash
cp .env.example .env
```

```env
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here

# Toggle to 'true' for offline demonstration without internet or API keys
OFFLINE_MODE=false

DATABASE_URL=sqlite:///./analysis_history.db
HOST=127.0.0.1
PORT=8000
```

### 4. Running the Application
```bash
uvicorn backend.main:app --reload --port 8000
```

* **Analysis Terminal**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
* **Intelligence Registry**: [http://127.0.0.1:8000/history.html](http://127.0.0.1:8000/history.html)
* **Interactive API Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## License

Institutional Academic Project — Cyber Security Research.
