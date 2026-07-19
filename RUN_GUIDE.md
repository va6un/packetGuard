# 🏁 PacketGuard — Judges Presentation & Run Guide

This handbook is structured to assist you in executing a flawless live demonstration of **PacketGuard** for your project presentation and viva panel.

---

## 🛠️ Step 1: Presentation Setup (The Warm-up)

Perform these steps on the presentation laptop before the session begins.

### 📋 Prerequisites
*   **Python**: Version 3.10 or higher
*   **Web Browser**: Google Chrome, Firefox, or Microsoft Edge (Chrome/Firefox preferred)

### 1. Install Dependencies
Open your terminal inside the `PacketGuard` directory and run:
```bash
pip install -r requirements.txt
```

### 2. Reset the Database (Clean Slate)
To ensure the judges see a clean, fresh interface:
1.  Locate the project folder.
2.  If you see `packetguard.db`, delete it.
3.  The database will automatically initialize fresh on startup.

### 3. Launch the Server
```bash
python app.py
```
Open your browser and navigate to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 📡 Step 2: Input CSV Generation

Be prepared to show how raw captures are converted into the PacketGuard format.

> [!IMPORTANT]
> The application processes captures formatted in the **tshark explicit-field CSV format**.

### The tshark Export Command
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

> [!TIP]
> **Why tshark fields?**  
> If the judges ask why you didn't use the standard Wireshark GUI CSV export:
> *   *The default Wireshark CSV merges multiple flags and text descriptors (e.g. `'0x00000002 (SYN)'`). This requires heavy text parsing.*
> *   *The `tshark -T fields` export gives isolated, numeric columns, enabling extremely fast vectorized operations in pandas.*

---

## 🎬 Step 3: Walkthrough Script for the Live Demo

Follow this flow for an impactful 5-minute presentation:

### Phase A: Upload Page & Input Format
1.  **Welcome**: Introduce the dashboard at `http://127.0.0.1:5000`.
2.  **Drag-and-Drop**: Highlight the modern drag-and-drop zone.
3.  **Recent History**: Point out the **Recent Analyses** history table showing previous sessions saved to SQLite.
4.  **Upload Action**: Upload the synthetic test capture:
    `sample_data/sample_capture.csv`
5.  Click **Analyse Capture** (point out the loading state: `⏳ Analysing…`).

### Phase B: Analyzing the Threat Report
Once redirected to `/results/<session_id>`:
1.  **Summary Cards**: Point out the stats overview:
    *   **Packets Analysed**: Show the count.
    *   **Rows Dropped**: Explain that malformed/IPv6 packets are logged here.
    *   **Threats Found**: Total alerts.
2.  **Detection Layer Breakdown**: Highlight the color-coded counters. They show exactly how many threats were caught by the Rule Engine, ML Engine, or both.
3.  **Threat Table**: Show the details:
    *   *SYN Flood*: Look at the reason column showing the exact ratio (`SYN/ACK ratio of 25.0 (25 SYN vs 0 ACK)`).
    *   *Port Scan (Fast)*: Point out the fast port scan row showing the short-window trigger.
    *   *Anomalous Flow (ML)*: Show the explainable AI feature: *it specifies which features drove the anomaly and by how many standard deviations* (e.g., `byte_volume is 4.3 standard deviations above the average`).
    *   *Rule + ML Merged*: Point out rows with the `rule-based + machine-learning` badge. Explain that the Consolidation module successfully merged overlapping alerts.

---

## 🔬 Step 4: Defense Q&A Cheatsheet

Expect these questions during your defense:

### Q1: Why use an unsupervised Isolation Forest model?
> **Answer**: *Supervised algorithms require labeled attack datasets, which are specific to the training environment and fail to capture unknown ("zero-day") attacks. Isolation Forest is unsupervised; it builds a tree structure of the current capture and flags anomalies as points that are structurally easy to isolate, working without any training data.*

### Q2: How does the ML explainability work?
> **Answer**: *Instead of treating the ML model as a black box, we calculate the z-scores for all features relative to the current capture. For any anomalous flow, the engine extracts the 1-2 features with the largest absolute z-score and formats them in plain English so analysts understand exactly what triggered the ML detection.*

### Q3: How are duplicate alerts prevented?
> **Answer**: *The consolidation layer merges Rule and ML engine alerts targeting the same directed flow `(src_ip, dst_ip)` if their time windows overlap. The consolidated row displays both sources in the `Layer` column (`rule-based + machine-learning`) and combines their reasoning.*

### Q4: How is high performance achieved in Python?
> **Answer**: *We utilize pandas vectorization. Calculating flow features and rules is done using vectorized aggregations (`groupby().agg()`), which compile to C. There are no manual row-by-row python loops (`for` loops) over the packet data.*
