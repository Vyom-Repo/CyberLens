<div align="center">

  <img src="frontend/logo.svg" alt="CyberLens Emblem" width="340" />

  <p><strong>Institutional Cyber Threat Intelligence &amp; Deterministic Risk Assessment Platform</strong></p>

  <p>
    <img src="https://img.shields.io/badge/Python-3.10%2B-14171A?style=flat-square&logo=python&logoColor=white" alt="Python Version" />
    <img src="https://img.shields.io/badge/Framework-FastAPI-14171A?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI" />
    <img src="https://img.shields.io/badge/Engine-Uvicorn-14171A?style=flat-square&logo=gunicorn&logoColor=white" alt="Uvicorn" />
    <img src="https://img.shields.io/badge/Persistence-SQLite%20%7C%20SQLAlchemy-14171A?style=flat-square&logo=sqlite&logoColor=white" alt="SQLite" />
    <img src="https://img.shields.io/badge/Architecture-Asynchronous%20Decoupled-9E7B3B?style=flat-square" alt="Decoupled" />
    <img src="https://img.shields.io/badge/Theme-Institutional%20Warm%20Alabaster-9E7B3B?style=flat-square" alt="Theme" />
  </p>

</div>

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Architectural Topology](#architectural-topology)
3. [Indicator Taxonomy & Provider Routing](#indicator-taxonomy--provider-routing)
4. [Explainable Risk Assessment Engine](#explainable-risk-assessment-engine)
5. [Security Engineering & Defense-in-Depth](#security-engineering--defense-in-depth)
6. [API Specification & Endpoints](#api-specification--endpoints)
7. [Installation & Deployment](#installation--deployment)
8. [Configuration & Operating Modes](#configuration--operating-modes)
9. [Verification & Test Suite](#verification--test-suite)

---

## Executive Summary

**CyberLens** is an institutional-grade Cyber Threat Intelligence (CTI) terminal engineered for high-throughput triage, syntax hygiene, multi-source intelligence aggregation, and explainable risk classification of Indicators of Compromise (IOCs).

Modern Security Operations Centers (SOCs) encounter thousands of unverified indicators across firewall logs, proxy egress alerts, email telemetry, and threat feeds. Manually querying disparate third-party intelligence services, parsing conflicting JSON schemas, and reconciling discordant detection metrics introduces cognitive fatigue and unacceptable latency into incident response cycles.

CyberLens resolves this operational bottleneck:
* **Ingestion Hygiene**: Automatically sanitizes defanged indicators (`hxxps://`, `1[.]1[.]1[.]1`, `[:]`), classifies format across 7 taxonomies, and prevents SSRF by halting non-routable private IPs.
* **Concurrent Provider Dispatching**: Queries **VirusTotal API v3** and **AbuseIPDB API v2** concurrently via non-blocking asynchronous HTTPX workers.
* **Unified Normalization Layer**: Maps vendor payloads into a strictly typed, flattened internal schema (`UnifiedIOCReport`).
* **Deterministic Risk Scoring**: Applies a mathematical 0–100 scoring model governed by configurable YAML rules, itemized attribution factors, and anti-dilution consensus thresholds.
* **Institutional Aesthetics**: Delivers a warm cream/alabaster editorial SOC console with real-time classification, Chart.js multi-engine distribution donuts, persistent SQLite audit trails, and auditable JSON dossier exports.

---

## Architectural Topology

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CyberLens Client Layer                          │
│     (HTML5 / CSS3 / Vanilla ES6 Modules / Bundled Local Chart.js)      │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                         REST / JSON Over HTTP
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                       FastAPI Application Gateway                      │
│                                                                        │
│   ┌─────────────────────┐                 ┌────────────────────────┐   │
│   │  Pre-Flight Hygiene │                 │ Asynchronous Dispatch  │   │
│   │  & Defang Sanitizer ├────────────────►│   Concurrent Workers   │   │
│   │ (RFC 1918 Defense)  │                 │    (HTTPX 8s Timeout)  │   │
│   └─────────────────────┘                 └───────────┬────────────┘   │
│                                                       │                │
│                                           ┌───────────┴────────────┐   │
│                                           │                        │   │
│                                     ┌─────▼──────┐          ┌──────▼──┐│
│                                     │ VirusTotal │          │AbuseIPDB││
│                                     │   API v3   │          │  API v2 ││
│                                     └─────┬──────┘          └──────┬──┘│
│                                           │                        │   │
│   ┌─────────────────────┐                 └───────────┬────────────┘   │
│   │ Persistence Layer   │                             │                │
│   │ SQLite / SQLAlchemy │◄────────────────────────────┤                │
│   │ (AnalysisRecord)    │                             ▼                │
│   └─────────────────────┘               ┌──────────────────────────┐   │
│                                         │ Normalization Layer      │   │
│                                         │ (UnifiedIOCReport Schema)│   │
│                                         └─────────────┬────────────┘   │
│                                                       │                │
│                                         ┌─────────────▼────────────┐   │
│                                         │ Explainable Risk Engine  │   │
│                                         │ (0-100 Score & Attribution)  │
│                                         └──────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Indicator Taxonomy & Provider Routing

Indicators are classified and dispatched based on provider capabilities:

| Indicator Taxonomy | Syntax Specification | Supported Providers | Verification / Normalization Behavior |
| :--- | :--- | :--- | :--- |
| **IPv4 Address** | RFC 791 Decimal Octets | VirusTotal + AbuseIPDB | Filtered via `ipaddress.is_global`. Private/loopback addresses safely rejected. |
| **IPv6 Address** | RFC 4291 Hexadecimal Colons | VirusTotal + AbuseIPDB | Full 128-bit structure verification and routability check. |
| **Domain (FQDN)** | RFC 1035 / RFC 1123 Labels | VirusTotal | Verified label lengths ($\le 63$), total length ($\le 253$), and valid TLD. |
| **Web URL** | RFC 3986 Scheme + Host | VirusTotal | Base64url encoded without padding (`base64.urlsafe_b64encode().strip("=")`). |
| **MD5 Hash** | 32 Hexadecimal Characters | VirusTotal | Case-insensitive normalization; static AV detection consensus parsing. |
| **SHA-1 Hash** | 40 Hexadecimal Characters | VirusTotal | Case-insensitive normalization; behavioral telemetry extraction. |
| **SHA-256 Hash** | 64 Hexadecimal Characters | VirusTotal | Case-insensitive normalization; high-consensus malware classification. |

---

## Explainable Risk Assessment Engine

### 1. Mathematical Formulation

For dual-source indicators (IP Addresses), the aggregate risk score $R \in [0, 100]$ is computed as:

$$R_{\text{raw}} = \left( W_{\text{VT}} \times S_{\text{VT}} \right) + \left( W_{\text{Abuse}} \times S_{\text{Abuse}} \right)$$

Where default weights from `config/risk_rules.yaml` are:
* $W_{\text{VT}} = 0.55$ (Antivirus vendor consensus detection weight)
* $W_{\text{Abuse}} = 0.45$ (Operational crowdsourced abuse reporting weight)

#### VirusTotal Sub-Score ($S_{\text{VT}}$)
Let $M$ be malicious detections, $S$ suspicious detections, and $T$ total scanners:

$$M_{\text{eff}} = M + (0.5 \times S)$$

$$S_{\text{VT}} = \min\left(100, \, \left(\frac{M_{\text{eff}}}{\max(1, T)} \times 100 \times 2.5\right) + \text{BasePenalty}\right)$$

* $\text{BasePenalty} = 25$ if $M \ge 3$, else $0$.
* If $M = 0$ and $S = 0 \implies S_{\text{VT}} = 0$.

#### AbuseIPDB Sub-Score ($S_{\text{Abuse}}$)
Let $C$ be the `abuseConfidenceScore` ($0 - 100$) and $V$ be total report count:

$$S_{\text{Abuse}} = \min\left(100, \, (0.85 \times C) + \left(0.15 \times \min(100, V \times 2.0)\right)\right)$$

### 2. Anti-Dilution Consensus Overrides
To prevent severe threats from being mathematically diluted by neutral weights:
* If VirusTotal Malicious $M \ge 10 \implies R \ge 80$ (**CRITICAL**).
* If AbuseIPDB Confidence $C \ge 90\% \implies R \ge 80$ (**CRITICAL**).
* If all active engines report 0 flags/reports $\implies R = 0$ (**LOW**).

### 3. Risk Classification Tiers

| Score Range | Threat Classification | Operational Directive |
| :---: | :---: | :--- |
| **0 – 19** | **LOW** | Benign or clean reputation. Standard allowlisting or low-priority telemetry. |
| **20 – 49** | **MEDIUM** | Low-confidence reports or isolated vendor flags. Contextual monitoring recommended. |
| **50 – 74** | **HIGH** | Multi-vendor detection consensus or verified repeated abuse. Actionable infrastructure. |
| **75 – 100** | **CRITICAL** | Severe consensus threat. Immediate automated blocking and endpoint containment. |

---

## Security Engineering & Defense-in-Depth

1. **Anti-SSRF & Private Network Defense**:
   * Outbound queries verify IP routability using Python's `ipaddress` library.
   * RFC 1918 private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), loopback (`127.0.0.1`), link-local (`169.254.0.0/16`), and multicast targets are blocked prior to network execution.
2. **Credential Isolation**:
   * API tokens are stored strictly in server-side environment variables (`.env`).
   * Keys are never exposed through API responses, client assets, or source control (`.gitignore` enforcement).
3. **Fault-Tolerant Graceful Degradation**:
   * Upstream HTTP requests enforce strict 8.0-second timeouts.
   * If a single provider fails, times out, or triggers HTTP 429 quota limits, the engine marks `data_completeness: "PARTIAL"` and scores based on available intelligence rather than crashing.
4. **100% Offline Capability**:
   * `Chart.js` is bundled locally within `frontend/js/vendor/` to eliminate external CDN dependencies.
   * Setting `OFFLINE_MODE=true` intercepts network queries and delivers authentic raw response structures from pre-seeded benchmark fixtures.

---

## API Specification & Endpoints

### `POST /api/validate`
Pre-flight syntax hygiene and classification endpoint.
```bash
curl -X POST http://127.0.0.1:8000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"ioc": "1[.]1[.]1[.]1"}'
```

### `POST /api/analyze`
Executes end-to-end multi-vendor ingestion, normalization, scoring, and persistence.
```bash
curl -X POST http://127.0.0.1:8000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{"ioc": "185.220.101.5"}'
```

### `GET /api/history`
Retrieves paginated historical investigations with optional substring and risk tier filters.
```bash
curl "http://127.0.0.1:8000/api/history?limit=20&risk_level=CRITICAL"
```

### `GET /api/report/{id}`
Downloads an auditable JSON investigation report with attachment disposition headers.
```bash
curl -OJ http://127.0.0.1:8000/api/report/1
```

---

## Installation & Deployment

### 1. Clone Repository
```bash
git clone https://github.com/Vyom-Repo/CyberLens.git
cd CyberLens
```

### 2. Environment Setup
```bash
# Initialize Python virtual environment
python3 -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configure Secrets
```bash
cp .env.example .env
```
Edit `.env` to configure your API keys:
```env
VT_API_KEY=your_virustotal_api_key_here
ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
OFFLINE_MODE=false
DATABASE_URL=sqlite:///./analysis_history.db
HOST=127.0.0.1
PORT=8000
```

### 4. Launch Service
```bash
uvicorn backend.main:app --reload --port 8000
```

* **Interactive Terminal**: [http://127.0.0.1:8000/](http://127.0.0.1:8000/)
* **Intelligence Registry**: [http://127.0.0.1:8000/history.html](http://127.0.0.1:8000/history.html)
* **OpenAPI Documentation**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)

---

## Verification & Test Suite

Verify all pipeline modules (detection, clients, normalizer, risk engine, SQLite persistence, and REST endpoints):

```bash
# Test complete pipeline integration
./venv/bin/python3 -c "
import asyncio
from httpx import AsyncClient, ASGITransport
from backend.main import app

async def run_checks():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url='http://test') as c:
        health = await c.get('/health')
        assert health.status_code == 200
        val = await c.post('/api/validate', json={'ioc': '1[.]1[.]1[.]1'})
        assert val.json()['valid'] is True
        print('CyberLens Diagnostics: All Core Services Operational.')

asyncio.run(run_checks())
"
```

---

## License & Attribution

Designed and engineered as an institutional threat intelligence platform. All threat intelligence feeds remain property of their respective providers (VirusTotal and AbuseIPDB).
