# DNS Tunneling Detection System
### Machine Learning Algorithms for DNS Tunneling Detection
**B.Sc. Final Year Project — Mewar International University, Faculty of Computing**

---

## What This System Does

This system monitors DNS (Domain Name System) network traffic in real time and uses a trained **Random Forest Machine Learning model** to automatically detect **DNS Tunneling attacks** — a technique hackers use to secretly steal data or send remote commands by hiding information inside ordinary-looking DNS requests.

When a suspicious DNS query is detected, the system:
- Calculates the **Shannon Entropy** (randomness score) of the domain string
- Extracts **9 behavioral features** from the query
- Runs it through the **trained ML classifier** (100% accuracy on test data)
- Logs the threat to the database
- Displays a **real-time alert on the web dashboard**

---

## About the Database

> **No external database application is needed.**

The system uses **SQLite** — a self-contained database that is built directly into Python. It creates a single file called `dns_security.db` in the project folder. You do not need to install MySQL, PostgreSQL, or any database software. The file is created automatically the first time you run the application.

**Database location:**
```
DNS Tunneling Detection System/
└── dns_security.db     ← created automatically on first run
```

The database contains 3 tables (3rd Normal Form compliant):
- `Client_Devices` — tracks source IP addresses of monitored endpoints
- `DNS_Logs` — stores every DNS query with its ML classification result
- `Threat_Alerts` — stores only the malicious (tunneling) queries for fast alert queries

---

## Project File Structure

```
DNS Tunneling Detection System/
│
├── README.md            ← This file
├── requirements.txt     ← Python package list
│
├── features.py          ← Shannon entropy + 9-feature extraction engine
├── database.py          ← SQLite 3NF database schema and logging functions
├── classifier.py        ← Loads trained model and classifies DNS queries
├── train_model.py       ← Generates synthetic data and trains the Random Forest
├── simulate.py          ← Simulates live DNS traffic (no root/admin needed)
├── sniffer.py           ← Captures real live DNS packets (requires root/admin)
├── app.py               ← Streamlit real-time web dashboard
│
├── dns_rf_model.pkl     ← Trained Random Forest model (created by train_model.py)
└── dns_security.db      ← SQLite database (created automatically on first run)
```

---

## System Requirements

| Requirement | Minimum |
|-------------|---------|
| Operating System | Windows 10/11, Ubuntu 20.04+, macOS 12+ |
| Python | Version 3.9 or higher |
| RAM | 4 GB |
| Disk Space | 500 MB |
| Network | Required for live sniffing only |

---

## Step-by-Step Installation Guide

### Step 1 — Verify Python is Installed

Open a terminal (Command Prompt on Windows, Terminal on Linux/macOS) and run:

```bash
python3 --version
```

You should see something like `Python 3.10.12`. If you see an error, download Python from https://python.org and install it first.

---

### Step 2 — Navigate to the Project Folder

```bash
cd "DNS Tunneling Detection System"
```

---

### Step 3 — Install All Required Packages

Run this single command to install every dependency the system needs:

```bash
pip3 install streamlit pandas numpy scikit-learn plotly joblib scapy
```

On some Linux systems (Ubuntu/Debian) if you get a system package warning, add the flag:

```bash
pip3 install --break-system-packages streamlit pandas numpy scikit-learn plotly joblib scapy
```

**What each package does:**

| Package | Purpose |
|---------|---------|
| `streamlit` | Powers the real-time web dashboard |
| `pandas` | Data manipulation and table display |
| `numpy` | Numerical computation for ML features |
| `scikit-learn` | Random Forest and SVM ML algorithms |
| `plotly` | Interactive charts and graphs |
| `joblib` | Saves and loads the trained ML model |
| `scapy` | Live network packet capture (for sniffer only) |

**Verify installation succeeded:**
```bash
python3 -c "import streamlit, pandas, numpy, sklearn, plotly, joblib; print('All packages installed OK')"
```

---

### Step 4 — Train the Machine Learning Model

This only needs to be done **once**. It generates 10,000 synthetic DNS samples and trains the Random Forest classifier:

```bash
python3 train_model.py
```

Expected output:
```
Generating 5000 benign + 5000 malicious samples...
Training Random Forest (100 trees)...

==================================================
  MODEL PERFORMANCE EVALUATION
==================================================
  Accuracy  : 100.00%
  Precision : 100.00%
  Recall    : 100.00%
  F1 Score  : 100.00%
==================================================
Model saved to dns_rf_model.pkl
```

This creates the file `dns_rf_model.pkl` in your project folder.

> **Note:** If you skip this step, the system still works using built-in rule-based thresholds as a fallback. But training the model first gives you the full ML-powered detection.

---

## How to Run the System

You need **two terminal windows open at the same time**.

---

### Terminal 1 — Start the Traffic Simulator

The simulator generates a continuous stream of realistic DNS traffic (80% benign, 20% malicious) and feeds it into the database in real time. This is what makes the dashboard show live data.

```bash
python3 simulate.py
```

You will see output like this:
```
DNS Traffic Simulator running — press Ctrl+C to stop.
  Interval: 1.5s | Malicious rate: 20%

[      ] 192.168.3.147  A      H=2.84  Risk=  0.0%  www.google.com
[THREAT] 192.168.2.88   TXT    H=4.61  Risk=100.0%  z9xkq2mr7plnbvta3ychd0e8j1.c2server.net
[      ] 192.168.1.205  A      H=3.04  Risk=  0.0%  api.github.com
[THREAT] 192.168.4.112  TXT    H=4.58  Risk=100.0%  6162636465666768696a6b.tunnel.org
```

Leave this running — **do not close it**.

---

### Terminal 2 — Launch the Web Dashboard

```bash
streamlit run app.py
```

The terminal will show:
```
You can now view your Streamlit app in your browser.

  Local URL: http://localhost:8501
  Network URL: http://192.168.x.x:8501
```

Open your browser and go to: **http://localhost:8501**

---

## What to Expect on the Dashboard

When you open the dashboard you will see:

### Top Metrics Bar
Four live counters showing:
- **Total DNS Queries Scanned** — total number of DNS queries processed
- **Malicious Tunnels Detected** — count of threats found (shown in red)
- **Benign Queries Passed** — clean traffic that passed inspection
- **Monitored Endpoint Devices** — number of unique IP addresses seen

### Three Charts (middle section)
1. **Traffic Classification Pie Chart** — shows the ratio of benign (green) vs tunneling (red) traffic
2. **Shannon Entropy Histogram** — shows the distribution of entropy scores; malicious queries cluster at entropy > 4.0
3. **DNS Record Type Bar Chart** — shows breakdown of A, AAAA, TXT, MX, CNAME record types

### Risk Score Stream Chart
A scatter plot of the last 100 queries plotted by risk score percentage. Green dots = benign, red dots = tunneling. An orange dashed line at 50% marks the detection threshold.

### Threat Alerts Table
A live table listing every detected DNS tunneling incident with:
- Alert ID, detection timestamp, source IP address
- The full malicious query string payload
- Shannon Entropy score and ML risk percentage
- Acknowledgement status

You can **acknowledge an alert** by entering its Alert ID and clicking Acknowledge.
You can **export all alerts** to a CSV file for reporting using the download button.

### Full Traffic Log (collapsed)
Click "View Full DNS Traffic Log" at the bottom to see all 200 most recent queries. Malicious rows are highlighted in red.

### Auto-Refresh
The dashboard **automatically refreshes every 3 seconds** so you see new data without reloading the page.

---

## Optional: Live Packet Capture (Real Network Traffic)

If you want to capture **real DNS traffic from your actual network** instead of simulated traffic, run the sniffer with administrator/root privileges:

**On Linux/macOS:**
```bash
sudo python3 sniffer.py
```

**On Windows (run Command Prompt as Administrator):**
```bash
python3 sniffer.py
```

> **Important:** This requires administrator/root access because it reads raw network packets. The simulator (`simulate.py`) works without any special permissions and is recommended for testing and demonstration.

---

## Quick Reference — All Commands

| Command | What it does |
|---------|-------------|
| `pip3 install -r requirements.txt` | Install all packages at once |
| `python3 train_model.py` | Train the ML model (run once) |
| `python3 simulate.py` | Start live traffic simulation |
| `streamlit run app.py` | Launch the web dashboard |
| `sudo python3 sniffer.py` | Capture real network traffic (optional) |
| `python3 database.py` | Re-initialize the database if needed |

---

## Troubleshooting

**"Module not found" error**
Run: `pip3 install --break-system-packages streamlit pandas numpy scikit-learn plotly joblib`

**Dashboard shows "No data yet"**
Make sure `simulate.py` is running in a separate terminal window.

**"Permission denied" on sniffer.py**
Run with `sudo python3 sniffer.py` on Linux/macOS, or as Administrator on Windows.
Alternatively, use `simulate.py` which needs no special permissions.

**Dashboard page keeps reloading/crashing**
This is the auto-refresh working normally. If it becomes too fast, open `app.py` and change `time.sleep(3)` to `time.sleep(5)`.

**"dns_rf_model.pkl not found"**
Run `python3 train_model.py` first to generate the trained model file.

**Port 8501 already in use**
Run: `streamlit run app.py --server.port 8502` and open `http://localhost:8502`

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| ML Algorithm | Random Forest (scikit-learn, 100 trees) |
| Feature Engineering | Shannon Entropy, 9 behavioral features |
| Database | SQLite 3 (built into Python, no install needed) |
| Backend | Python 3.10+ |
| Frontend Dashboard | Streamlit 1.35+ |
| Charts | Plotly Express |
| Live Capture | Scapy |
| Model Persistence | Joblib |

---

## Authors

**B.Sc. Final Year Project**
Mewar International University
Faculty of Computing
