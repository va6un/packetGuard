# 🛡️ PacketGuard

**PacketGuard** is a lightweight, web-based network threat detection and analysis tool built using Flask, pandas, and scikit-learn. It processes exported network traffic metadata from Wireshark/tshark, extracts flow-level features, evaluates threats through a hybrid detection engine (hand-crafted rules + Isolation Forest machine learning), and serves a consolidated, interactive report.

---

## 🚀 Key Features

*   **Two-Layer Analysis Engine**: Merges traditional deterministic rules with an unsupervised `IsolationForest` ML model for anomaly detection.
*   **Vectorized Data Processing**: Powered entirely by vectorized pandas operations—no manual row-by-row packet looping for maximum performance.
*   **Explainable Machine Learning**: Rather than outputting a "black box" anomaly flag, the ML layer calculates feature z-scores to explain *which* specific network features drove the anomaly.
*   **Intelligent Consolidation**: Automatically merges overlapping rule-based and ML detections targeting the same flow to ensure zero duplication in the final reports.
*   **SQLite Audit Persistence**: Persists upload audits and threat logs in SQLite via SQLAlchemy ORM for bookmarkable, permanent analysis reports.

---

## 🛠️ Tech Stack

*   **Backend framework**: Flask
*   **Data Analysis**: pandas & numpy
*   **Machine Learning**: scikit-learn (`IsolationForest`, `StandardScaler`)
*   **Database ORM**: SQLAlchemy (SQLite)
*   **Frontend**: Jinja2 Server-Rendered templates + Custom Vanilla CSS (Dark glassmorphism theme)
*   **Unit Testing**: pytest

---

## 📋 Table of Contents

1. [Quickstart Setup](#-quickstart-setup)
2. [tshark CSV Generation](#-tshark-csv-generation)
3. [Architecture Flow](#-architecture-flow)
4. [Detection Signature Reference](#-detection-signature-reference)
5. [Limitations](#-limitations)

---

## ⚡ Quickstart Setup

> [!NOTE]
> Ensure you have **Python 3.10+** installed before proceeding.

### 1. Clone & Navigate
```bash
git clone https://github.com/va6un/packetGuard.git
cd packetGuard
```

### 2. Set Up Virtual Environment (Recommended)
```bash
# Windows
python -m venv .venv
.venv\Scripts\activate

# macOS / Linux
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Server
```bash
python app.py
```
Open **[http://127.0.0.1:5000](http://127.0.0.1:5000)** in your browser.

### 5. Running the Test Suite
Ensure the code is robust and green:
```bash
python -m pytest tests/ -v
```

---

## 📡 tshark CSV Generation

PacketGuard standardizes on the **tshark explicit-field CSV export format**. This provides clean, isolated, numeric data columns rather than display-formatted compound strings.

Run this terminal command to export your `.pcap` or `.pcapng` file:

```bash
tshark -r capture.pcap \
    -T fields \
    -e frame.time_relative \
    -e ip.src \
    -e ip.dst \
    -e tcp.srcport \
    -e udp.srcport \
    -e tcp.dstport \
    -e udp.dstport \
    -e _ws.col.Protocol \
    -e frame.len \
    -e tcp.flags.syn \
    -e tcp.flags.ack \
    -e tcp.flags.reset \
    -e eth.src \
    -e eth.dst \
    -E header=y -E separator=, -E quote=d -E occurrence=f \
    > capture.csv
```

> [!WARNING]
> Do not use Wireshark's GUI *Export Packet Dissections as CSV*. It compresses multiple flags and descriptors into textual fields (e.g. `'0x00000002 (SYN)'`), which cannot be efficiently parsed by the pandas ingestion layer.

---

## 🏗️ Architecture Flow

Data flows strictly in one direction from capture ingestion through to the SQLite database and presentation layer:

```
┌──────────────┐      ┌────────────────────┐      ┌───────────────┐
│  Ingestion   │ ───> │ Feature Extraction │ ───> │  Rule Engine  │ ───┐
│ (ingestion)  │      │(feature_extraction)│      │ (rule_engine) │    │
└──────────────┘      └────────────────────┘      └───────────────┘    │    ┌───────────────┐
                                                            │          ├──> │ Consolidation │ ──> DB / UI
                                                            v          │    │(consolidation)│
                                                  ┌───────────────┐    │    └───────────────┘
                                                  │   ML Engine   │ ───┘
                                                  │  (ml_engine)  │
                                                  └───────────────┘
```

### Module Responsibilities

| Module | Responsibility |
| :--- | :--- |
| **Ingestion** (`ingestion.py`) | Schema validation, column normalization, type coercion (timestamps, ports, hex flags), packet cleanups, and dropping malformed/unsupported rows. |
| **Feature Extraction** (`feature_extraction.py`) | Directs packet streams into ordered flow pairs `(src_ip, dst_ip)` and aggregates stats across both 10-second (short) and full-session time windows. |
| **Rule Engine** (`rule_engine.py`) | Evaluates deterministic signature rules (SYN Flood ratios, fast port scans, slow port scans, and ARP spoofing checks). |
| **ML Engine** (`ml_engine.py`) | Fits an unsupervised `IsolationForest` to the flow table, scoring statistical outliers. Explains anomalies by reporting the top features by z-score magnitude. |
| **Consolidation** (`result_consolidation.py`) | Merges rules and ML flags, deduplicates overlapping flows, and assigns severity sorting weights. |
| **Persistence** (`db.py`) | SQLite database schema implementation utilizing UploadSession and DetectionResult models. |

---

## 🚨 Detection Signature Reference

| Threat Name | Analysis Window | Trigger Condition |
| :--- | :--- | :--- |
| **SYN Flood** | Short (10s) Window | `syn_ack_ratio > 5.0` AND `syn_count >= 20` |
| **Port Scan (Fast)** | Short (10s) Window | `unique_dst_ports >= 15` |
| **Port Scan (Slow)** | Full-Session Window | `unique_dst_ports >= 20` (suppressed if already caught by Fast Scan) |
| **ARP Spoofing** | Raw Packet DataFrame | Single `src_ip` mapped to multiple physical `eth.src` MAC addresses |
| **Anomalous Flow** | Full Feature Dataset | Scored outlier (`IsolationForest` predict == -1), explained by top z-scores |

---

## ⚠️ Limitations

> [!IMPORTANT]
> Keep the following constraints in mind during presentation/evaluation:
> *   **IPv4 Only**: IPv6 packets are identified and logged in the drop statistics, but explicitly skipped during analysis.
> *   **Unsupervised ML**: The Isolation Forest model is fit fresh on the uploaded capture data. It identifies statistical anomalies *relative to the capture itself*, rather than against a pre-trained external baseline.
> *   **No Live Capture**: Capturing must be performed externally using Wireshark, tcpdump, or tshark, then uploaded as a structured CSV.
