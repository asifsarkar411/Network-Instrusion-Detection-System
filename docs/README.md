# SOC-NIDS // Threat Command

**Real-time Network Intrusion Detection System**
*7-class ML detection · Hybrid rule-engine fusion · Professional SOC dashboard*


## Overview

SOC-NIDS is a capstone project that demonstrates real-time network intrusion detection
combining machine learning (XGBoost), signature-based rules, and unsupervised anomaly
detection in a weighted fusion architecture. The system captures live network traffic,
extracts flow-level features, classifies attacks in real-time, and presents results
in an 8-page professional dashboard.

### Attack Classes Detected

| # | Class | Training Samples | Detection Method |
|---|-------|:---:|---|
| 0 | **Benign** | 1.1M | ML + Rules |
| 1 | **DoS** | 124K | ML + Rules (high packet rate) |
| 2 | **PortScan** | 111K | ML + Rules (SYN flood detection) |
| 3 | **DDoS** | 67K | ML (behavioral pattern) |
| 4 | **BruteForce** | 5K | ML (authentication pattern) |
| 5 | **Botnet** | 516 | ML (C&C pattern) |
| 6 | **WebAttack** | 73 | Rules (SQLi, XSS, path traversal signatures) |

---

## Performance

Evaluated on CIC-IDS-2017 held-out test set (303K flows):

| Class | Precision | Recall | F1 | 95% CI |
|-------|:---:|:---:|:---:|:---:|
| Benign | 100% | 100% | 1.000 | 99.99–100% |
| DoS | 100% | 100% | 1.000 | 99.98–100% |
| PortScan | 100% | 100% | 1.000 | 99.98–100% |
| DDoS | 100% | 100% | 1.000 | 99.97–100% |
| BruteForce | 100% | 99.9% | 0.999 | 99.4–100% |
| Botnet | 100% | 100% | 1.000 | 96.7–100% |
| WebAttack | 100% | 100% | 1.000 | 79.4–100% |

**Overall: 100% Accuracy · 100% Weighted F1 · 5-Fold Cross-Validated**

---

## Important Caveats

1. **Dataset Limitations:** CIC-IDS-2017 is a controlled testbed where attacks
   have distinct flow patterns. These results are consistent with published
   literature (99%+ on this benchmark). Real-world NIDS with concept drift,
   encrypted traffic, and adversarial evasion would score lower.

2. **Minority Class Statistics:** WebAttack (16 test samples) and Botnet (110
   test samples) have wide confidence intervals. WebAttack detection in
   production relies on the signature-based rule engine.

3. **Attack Simulation:** Dashboard simulation buttons generate pre-formatted
   alerts for UI demonstration only — they bypass the detection pipeline.

4. **Single-Network Evaluation:** Model trained and tested on data from the
   same network environment. Cross-network generalization not evaluated.

---

## Quick Start

### Prerequisites
- Windows 10/11 with [Npcap](https://npcap.com) (WinPcap API-compatible mode)
- Python 3.11+
- Administrator privileges for packet capture

### Setup
```bash
git clone <repo-url>
cd soc-nids-dashboard
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Dataset:
Downloaded from CIC-IDS-2017 from UNB.
Place all *_plus.csv files in the data/ folder.


Dashboard Pages:
Page	Description
📡 Live Monitor	Real-time threat gauge, network map, radar, alert feed
📊 Threat Analysis	Attack distribution, timelines, top sources, bandwidth
🔍 Packet Inspector	Terminal-style live packet log with color-coded rows
🧠 ML Insights	Model metrics, SHAP explainability, ablation study
🌐 Threat Intelligence	GeoIP attack map, attacker profiling
📋 Reports	CSV, JSON, PDF export with session summaries
⚙️ Configuration	Detection parameters, interface settings
⚡ Performance	CPU, memory, latency, throughput monitoring


Architecture:

Capture → Flow Extraction → Hybrid Detection → Storage → Dashboard

scapy.sniff()       FlowExtractor      XGBoost ML        SQLite       Streamlit
Ring Buffer         25 features        Rule Engine       Alerts DB    8 pages
BPF Filter          GC Timeout         Iso. Forest                    Real-time
                                       Wtd. Fusion


Tech Stack:

Layer	        Technology
Capture	        scapy, Npcap
ML	            XGBoost, scikit-learn, SHAP, Isolation Forest
Rules	        Regex-based signature engine
Dashboard	    Streamlit, Plotly
Storage	        SQLite
Reports	        fpdf2
Fonts	        Orbitron, Inter, JetBrains Mono


Project Structure:

soc-nids-dashboard/
├── app.py                    # Dashboard entry
├── main.py                   # Headless pipeline
├── config.yaml               # Configuration
├── requirements.txt          # Dependencies
├── data/                     # CIC-IDS-2017 dataset
├── models/                   # Trained models
├── reports/                  # Evaluation charts
├── notebooks/                # Analysis scripts
├── docs/                     # Documentation
├── pages/                    # 8 dashboard pages
└── src/                      # 12 source modules


License:
MIT — see LICENSE file.


Acknowledgments:
CIC-IDS-2017 dataset: Canadian Institute for Cybersecurity
SHAP: Lundberg & Lee (2017)
Streamlit: Snowflake Inc.




### Document 2: Architecture Documentation

# SOC-NIDS Architecture

## System Design

SOC-NIDS follows a layered pipeline architecture:
┌─────────────────────────────────────────────────────────┐
│ PRESENTATION LAYER                                      │
│ Streamlit Dashboard · 8 Pages · Real-time Updates       │
├─────────────────────────────────────────────────────────┤
│ STORAGE LAYER                                           │
│ SQLite · Alerts · Flow Features · JSON Metadata         │
├─────────────────────────────────────────────────────────┤
│ DETECTION LAYER                                         │
│ ┌──────────┐ ┌──────────┐ ┌──────────────────┐          │
│ │ XGBoost  │ │ Rule     │ │ Isolation        │          │
│ │ 7-Class  │ │ Engine   │ │ Forest           │          │
│ └────┬─────┘ └────┬─────┘ └────────┬─────────┘          │
│    └──────────────┼───────────────┘                     │
│ ▼                                                       │
│ Weighted Fusion                                         │
│ Final = Wr×Rule + Wm×ML                                 │
├─────────────────────────────────────────────────────────┤
│ EXTRACTION LAYER                                        │  
│ Flow Extractor · 25 Features · Garbage Collection       │
├─────────────────────────────────────────────────────────┤
│ CAPTURE LAYER                                           │
│ scapy · Ring Buffer · BPF Filter · Live Interface       │
└─────────────────────────────────────────────────────────┘



## Component Details

### 1. Capture Layer (`src/capture.py`)

Captures live network packets via scapy with kernel-level BPF filtering.

**Key Design Decisions:**
- **Ring Buffer:** `collections.deque(maxlen=10000)` prevents unbounded memory growth
- **BPF Filter:** `tcp or (udp and port 53)` drops streaming video/music at kernel level
- **Background Thread:** Daemon thread for non-blocking capture
- **Configurable:** Interface, duration, buffer size from `config.yaml`

### 2. Flow Extraction (`src/flow_extractor.py`)

Groups raw packets into bidirectional flows and computes statistical features.

**Flow Definition:**
- 5-tuple key: `(src_ip, dst_ip, src_port, dst_port, protocol)`
- Normalized for bidirectionality
- 60-second inactivity timeout (garbage collector thread)

**25 Features Extracted:**
- Duration, packet/byte counts (forward + backward)
- Packet length statistics (mean, std dev)
- Inter-arrival time statistics
- TCP flag distributions (SYN, FIN, RST, PSH, ACK, URG)
- Rate features (packets/sec, bytes/sec)

### 3. Hybrid Detection (`src/analysis_engine.py`, `src/rule_engine.py`)

Three detection methods combined via weighted fusion.

#### XGBoost ML Model
- Trained on 2.1M flows from CIC-IDS-2017
- 86 features, 7 classes
- 100% weighted F1 (5-fold CV)
- SHAP explainability for every prediction

#### Rule Engine
- PortScan: >50 unique ports in 60 seconds
- DoS: >500 packets in 10 seconds or >100 pps
- WebAttack: SQL injection, XSS, path traversal regex patterns

#### Isolation Forest
- Unsupervised anomaly detection
- 10% contamination rate
- Supplementary layer for zero-day threats

#### Weighted Fusion
If Rule_Score > 0.8 AND ML_Score < 0.1:
Final = Rule_Score (Rule dominates when ML uncertain)
Else:
Final = 0.4 × Rule_Score + 0.6 × ML_Score

Alert if Final >= 0.7



### 4. Storage Layer (`src/storage.py`)

SQLite database with indexed tables for alerts and flow statistics.

### 5. Dashboard Layer (`pages/`, `src/dashboard_components.py`)

8-page Streamlit dashboard with:
- Glassmorphism dark theme
- Plotly charts with consistent professional styling
- Auto-refresh every 2.5-3 seconds
- Orbitron (headings) + Inter (body) + JetBrains Mono (code)

## Data Flow
Network Interface
│
▼
scapy.sniff() ──► Ring Buffer ──► Flow Extractor
│
▼
Analysis Engine
┌─────────┼─────────┐
▼ ▼ ▼
XGBoost Rules IsoForest
└─────────┼─────────┘
▼
Weighted Fusion
│
▼
SQLite Database
│
▼
Streamlit Dashboard



## Design Rationale

| Decision                   | Why                                                       |
|----------                  |-----                                                      |
| Streamlit over React       | Python-native, rapid development, sufficient for capstone |
| XGBoost over Deep Learning | Better on tabular data, built-in feature importance       |
| Hybrid over ML-only        | Rule engine covers WebAttack (limited samples)            |
| Ring Buffer                | Constant memory regardless of capture duration            |
| SQLite                     | Zero-config, file-based, single-machine sufficient        |

## Limitations

- Packet drops at >10K pps (mitigated by BPF filter)
- WebAttack: 73 training samples (rule engine compensates)
- Single-machine deployment
- No encrypted traffic analysis
- Dataset-specific performance (CIC-IDS-2017 is clean/controlled)
Document 3: User Guide
powershell
notepad docs/user_guide.md
markdown
# SOC-NIDS User Guide

## Installation

### Step 1: Prerequisites
- Windows 10/11
- [Npcap](https://npcap.com) — check "WinPcap API-compatible Mode" during install
- Python 3.11+
- Git


### Step 2: Setup
```bash
git clone <repo-url>
cd soc-nids-dashboard
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt


Step 3: Dataset
Download CIC-IDS-2017 from unb.ca/cic/datasets/ids-2017.html
Place these files in data/:

monday_plus.csv

tuesday_plus.csv

wednesday_plus.csv

thursday_plus.csv

friday_plus.csv



Step 4: Train Model
bash
python src/train_model.py



Step 5: Launch
bash
streamlit run app.py
Open http://localhost:8501



Step 6: Configure Interface
bash
python -c "from scapy.all import IFACES; IFACES.show()"
Find your active interface (with your IP address).
Update config.yaml or use the Configuration page.

Using the Dashboard
Starting Monitoring
Go to 📡 Live Monitor

Click ▶ START

Packets, flows, and alerts appear in real-time

Viewing Live Packets
Go to 🔍 Packet Inspector

See terminal-style log with color-coded rows

Filter by protocol, risk level, or search IPs

Use ⏸️ Pause Stream to freeze


Understanding Alerts
🔴 High: Immediate threat (DoS, PortScan)

🟡 Medium: Suspicious activity (WebAttack, BruteForce)

🟢 Low: Benign traffic below threshold
    

Attack Simulation (Demo Only)
⚠️ These generate pre-formatted alerts for UI demonstration.
They do NOT test the ML detection pipeline.

Go to 📡 Live Monitor → expand ⚔️ ATTACK SIMULATION

Click buttons to generate test alerts

Exporting Reports
Go to 📋 Reports

Download CSV or JSON

Expand 📄 Generate PDF Report for professional documentation

Configuration
Go to ⚙️ Configuration

Adjust Rule Weight, Alert Threshold

Modify interface, BPF filter, flow timeout

Click 💾 Save Configuration



Troubleshooting

Issue	              Solution
PermissionError	      Run PowerShell as Administrator
Interface             not found	Update interface name in config.yaml
No                    packets	Try bpf_filter: "" temporarily
Dashboard             blank	Check http://localhost:8501
Model                 not found	Run train_model.py first
High                  CPU	Reduce ring_buffer_size in config.yaml
File                  Reference
Path	              Purpose
config.yaml	          All system configuration
data/	              CIC-IDS-2017 CSV files
models/	              Trained models and preprocessors
reports/	          Generated charts and evaluation
data/nids_alerts.db	  Alert database




