# PacketGuard 🛡️

**PacketGuard** is a lightweight web-based network threat detection tool built as an MCA mini-project. It accepts a Wireshark/tshark packet capture export (CSV) and runs it through a **two-layer detection engine** — hand-crafted rules plus Isolation Forest machine learning — to produce a single, deduplicated, human-readable threat report.

---

## Table of Contents

1. [Setup](#setup)
2. [How to Generate the Input CSV](#how-to-generate-the-input-csv)
3. [Running the App](#running-the-app)
4. [Running the Tests](#running-the-tests)
5. [Architecture & Module Responsibilities](#architecture--module-responsibilities)
6. [Detection Rules Reference](#detection-rules-reference)
7. [Limitations](#limitations)

---

## Setup

**Prerequisites:** Python 3.10+, `pip`, `tshark` (for generating input files).

```bash
# 1. Clone / download the project
cd PacketGuard

# 2. (Optional) Create a virtual environment
python -m venv .venv
.venv\Scripts\activate        # Windows
# source .venv/bin/activate   # macOS / Linux

# 3. Install dependencies
pip install -r requirements.txt
```

---

## How to Generate the Input CSV

PacketGuard requires the **tshark explicit-field CSV format**, not the default Wireshark GUI export. The tshark format gives one clean, unambiguous value per column, which makes automated parsing reliable.

Run the following command on your `.pcap` or `.pcapng` file:

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

The resulting `capture.csv` is what you upload via the web UI.

> **Why not the Wireshark GUI export?**  
> Wireshark's "File → Export Packet Dissections → CSV" packs multiple decoded values into display-formatted strings (e.g. a single TCP flags column reads `"0x00000002 (SYN)"`). The tshark `-T fields` format gives each flag its own numeric column, which is unambiguous and trivially parseable.

---

## Running the App

```bash
python app.py
```

Open your browser at **http://127.0.0.1:5000**.

Upload any tshark-format CSV. The app will:
1. Ingest and validate the file.
2. Extract flow-level features (10-second and full-session windows).
3. Run rule-based detection (SYN Flood, Port Scan ×2, ARP Spoofing).
4. Run Isolation Forest anomaly detection.
5. Merge and deduplicate both layers' results.
6. Persist the results to `packetguard.db` (SQLite).
7. Redirect you to the report page at `/results/<session_id>`.

Reports can be revisited later — the URL is bookmarkable.

A synthetic sample file is included for testing:

```
sample_data/sample_capture.csv
```

It contains a clear SYN flood pattern (192.168.1.100 → 10.0.0.1) and a fast port scan (192.168.1.200 → 10.0.0.2). Upload it to verify the end-to-end pipeline.

---

## Running the Tests

```bash
python -m pytest tests/ -v
```

Each module has its own test file in `tests/`. Tests use small synthetic DataFrames — no real capture files are required (except the end-to-end ingestion test, which uses `sample_data/sample_capture.csv`).

Expected output: all tests pass.

---

## Architecture & Module Responsibilities

Data flows strictly left-to-right:

```
Ingestion → Feature Extraction → ┬─ Rule Engine ─┐
                                  └─ ML Engine   ─┴→ Consolidation → UI / DB
```

| File | Responsibility |
|---|---|
| `ingestion.py` | Read the uploaded CSV, validate schema, rename columns, coerce types, derive TCP flag strings, drop malformed rows. Returns a clean, typed DataFrame. |
| `feature_extraction.py` | Group packets into directed `(src_ip, dst_ip)` flows across two time windows (10-second buckets and full-session). Compute packet_count, byte_volume, packet_rate, unique_dst_ports, duration, SYN/ACK/RST counts, syn_ack_ratio, and protocol fractions — all via vectorized `groupby().agg()`. |
| `rule_engine.py` | Apply four hand-crafted detection rules to the feature table (SYN Flood, Fast Port Scan, Slow Port Scan) and directly to the packet DataFrame (ARP Spoofing). Returns a list of flag dicts with plain-English reason strings. |
| `ml_engine.py` | Fit `IsolationForest(contamination='auto', random_state=42)` on the flow features of the current capture (unsupervised, no pretrained model). Identify anomalies and explain each one by naming the 1–2 features with the largest absolute z-score. |
| `result_consolidation.py` | Merge rule-based and ML flags. When the same `(src_ip, dst_ip)` pair with overlapping windows is flagged by both layers, merge into one entry (`layer = "rule-based + machine-learning"`). Sort by threat severity, then src_ip. |
| `db.py` | SQLAlchemy ORM with two tables: `sessions` (upload audit) and `results` (per-flag persistence). Provides `init_db`, `save_session`, `save_results`, `get_session`, `get_results`. |
| `app.py` | Flask entrypoint. Two routes: `GET /` (upload form) and `POST /upload` (pipeline orchestration), plus `GET /results/<id>` (report from DB). Catches all custom ingestion exceptions and converts them to flash messages — no raw stack traces in the browser. |

---

## Detection Rules Reference

| Rule | Input | Trigger Condition |
|---|---|---|
| **SYN Flood** | Short-window (10s) features | `syn_ack_ratio > 5.0` AND `syn_count >= 20` |
| **Port Scan (Fast)** | Short-window (10s) features | `unique_dst_ports >= 15` within one 10-second window |
| **Port Scan (Slow)** | Full-session features | `unique_dst_ports >= 20` across the entire capture; suppressed if the same pair was already caught by the fast-scan rule |
| **ARP Spoofing** | Raw packet DataFrame | One IP address mapped to 2+ distinct MAC addresses across the capture |
| **Anomalous Flow (ML)** | Full feature table | `IsolationForest` scores the flow as an outlier (`predict() == -1`); reason string names the top 1–2 z-score features |

All thresholds are named constants in `rule_engine.py` — easy to adjust for your network baseline.

---

## Limitations

- **IPv4 only.** IPv6 packets are detected and counted in the drop report, but excluded from threat analysis. Re-run tshark with `--ipv4` to pre-filter if needed.
- **No live capture.** Traffic must be captured externally with Wireshark or tcpdump and exported with tshark before uploading.
- **No user authentication.** Single-user academic tool — do not expose to the public internet without adding auth.
- **No persistent ML model.** Isolation Forest is fitted fresh on each uploaded capture. It detects statistical outliers *within that capture*, not against a historical baseline.
- **No IPv6 support.** Designed and tested for IPv4 traffic only.
