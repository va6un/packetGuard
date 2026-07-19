# 🛡️ PacketGuard — Judges Presentation & Run Guide

This guide is designed to help you run a flawless, impressive live demonstration of **PacketGuard** for your project presentation/viva panel. It covers setup, capture generation, step-by-step presentation flow, and answers to common defense questions.

---

## 1. Quickstart Setup (For the Presentation Laptop)

Before the panel gathers, ensure all dependencies are installed and the database is initialized.

### Prerequisites
*   Python 3.10+
*   Google Chrome / Firefox (for the web interface)

### Step 1: Install Dependencies
Open your terminal in the project root directory and run:
```bash
pip install -r requirements.txt
```

### Step 2: Clear/Initialize the Database (Clean Slate)
To start with a clean demo database:
1.  Delete the existing `packetguard.db` file if it exists.
2.  The database will automatically initialize fresh on the first run.

### Step 3: Run the Application
Start the Flask local development server:
```bash
python app.py
```
Open your web browser and navigate to: **[http://127.0.0.1:5000](http://127.0.0.1:5000)**

---

## 2. How to Generate the CSV Input Files

Judges will want to know how real network packets make it into the application. Explain this process clearly.

### The Standard tshark Pipeline
PacketGuard processes captures generated via **tshark** (Wireshark's command-line tool). Run this command on any raw `.pcap` or `.pcapng` file to generate a compatible CSV:

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

### 💡 Presentation Tip: Why tshark instead of Wireshark's default CSV?
If the judges ask why you didn't use the standard Wireshark "Export as CSV" option:
> *"The default Wireshark CSV export produces display-formatted strings (e.g. mapping TCP flags into a single string like `'0x00000002 (SYN)'`). This is ambiguous and computationally expensive to parse. The `tshark -T fields` command outputs explicit, isolated, numeric data columns, enabling high-performance vectorized operations."*

---

## 3. Step-by-Step Live Demo Flow (Get the "Wow" Factor)

Follow this structure during your 5-minute presentation:

### Phase 1: The Index Page (Clean & Modern UI)
1.  Show the landing page **[http://127.0.0.1:5000](http://127.0.0.1:5000)**.
2.  Point out the **drag-and-drop zone**, clean branding, and clear tshark command instructions listed on the screen.
3.  Scroll down to show the **Recent Analyses** history table (empty or listing past sessions stored in SQLite).

### Phase 2: Upload and Analysis
1.  Click **Browse Files** (or drag) and select the pre-packaged sample file:
    `sample_data/sample_capture.csv`
2.  Click **Analyse Capture**.
3.  The button will change to **⏳ Analysing…** showing a polished loading state.

### Phase 3: The Threat Report (The Highlight)
Once complete, you will be redirected to the report page:
1.  **Summary Cards**: Show the panel the high-level stats: Packets Analysed, Rows Dropped (for malformed or IPv6 packets), Threats Found, and Active Layers.
2.  **Layer Breakdown Chips**: Point out the color-coded counters showing how many threats were caught by the Rule Engine, ML Engine, or **Both agreed**.
3.  **Threat Table**: Scroll through the sorted threat list:
    *   **SYN Flood**: Highlight the specific reason string showing the exact ratio (`SYN/ACK ratio of 25.0 (25 SYN vs 0 ACK)`).
    *   **Port Scan (Fast)**: Point out how it flagged scanning activities within a 10s window.
    *   **Anomalous Flow (ML)**: Show the explainable AI feature: *it does not just say "anomaly", it lists which features drove the anomaly and by how many standard deviations* (e.g., `byte_volume is 4.3 standard deviations above the average`).
    *   **Rule + ML Merged**: Show the rows labeled `rule-based + machine-learning` in the layer column, showing that both engines independently agreed on the threat.

---

## 4. Key Viva/Defense Questions & Answers

Be prepared to answer these technical questions from the judges:

#### Q1: "Why did you choose Isolation Forest instead of a Supervised ML model (like Random Forest)?"
> **Answer:** *"Supervised models require labeled training data (attack vs. benign), which is highly dependent on the environment they were trained on and fails to generalize to zero-day attacks. Isolation Forest is unsupervised; it models normal behavior of the current capture and flags anomalies as points that are structurally easy to isolate, requiring no prior training phase."*

#### Q2: "How does the app handle explainability for the ML layer?"
> **Answer:** *"Instead of treating the Isolation Forest as a black box, we calculate the z-scores for all features in the scaled dataset. For any flow flagged as an anomaly, the engine identifies the 1-2 features with the largest absolute z-score and reports them in plain English (e.g., `packet_rate is 5.2 standard deviations above the average`)."*

#### Q3: "How does the consolidation layer work?"
> **Answer:** *"If we showed Rule Engine flags and ML flags separately, the report would be cluttered with duplicate warnings for the same attack. The consolidation module merges flags targeting the same source/destination IP address that occur within overlapping time windows. It upgrades the detection layer metadata to `rule-based + machine-learning` and appends the ML rationale to the rule reason."*

#### Q4: "How is data processing optimized in Python?"
> **Answer:** *"We use pandas with vectorized operations for feature extraction. There are no manual row-by-row python loops (`for` loops) over the packet table. All aggregations and calculations are executed in C-optimized vectorized operations via pandas `groupby().agg()`."*

---

## 5. Summary of Key Files

If judges want to look at your code structure:
*   [ingestion.py](file:///c:/Users/kkff9/OneDrive/Desktop/PacketGuard/ingestion.py): Data cleaning, IPv4 validation, type coercion.
*   [feature_extraction.py](file:///c:/Users/kkff9/OneDrive/Desktop/PacketGuard/feature_extraction.py): Window-based flow feature calculation.
*   [rule_engine.py](file:///c:/Users/kkff9/OneDrive/Desktop/PacketGuard/rule_engine.py): Traditional signatures (SYN flood, port scans, ARP spoofing).
*   [ml_engine.py](file:///c:/Users/kkff9/OneDrive/Desktop/PacketGuard/ml_engine.py): Isolation Forest model fit per capture + z-score explanations.
*   [result_consolidation.py](file:///c:/Users/kkff9/OneDrive/Desktop/PacketGuard/result_consolidation.py): Result merging and deduplication.
*   [app.py](file:///c:/Users/kkff9/OneDrive/Desktop/PacketGuard/app.py) & [db.py](file:///c:/Users/kkff9/OneDrive/Desktop/PacketGuard/db.py): Flask controller, SQLite persistence via SQLAlchemy.
