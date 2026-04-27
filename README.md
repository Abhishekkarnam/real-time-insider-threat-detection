# Real-Time Insider Threat Detection Using Network Behavior Profiling

This project detects suspicious insider activity by collecting live system/network activity, building behavior profiles for users, scoring deviations, and displaying alerts in a Streamlit dashboard.

The original version used simulated data. This upgraded version supports **real-time monitoring using system-level and packet-level data collection**.

---

##  Project Idea

Insider threats are difficult to detect because attackers often have legitimate access.

Instead of relying on signatures or blacklists, this system:

- Learns **normal user behavior**
- Detects **deviations in real time**
- Raises alerts with **severity levels and reasons**

---

##  Examples of Suspicious Behavior

- Logging in at unusual hours  
- Connecting to rarely used destinations  
- Sudden spikes in upload/download volume  
- Abnormal access frequency  
- New source IP or device change  

---

##  Current Scope

This project includes:

- Real-time network collection using **psutil**
- Optional packet capture using **scapy**
- Continuous append-only CSV storage
- Compatibility with anomaly detection pipeline
- Per-user behavior profiling
- Lightweight anomaly scoring engine
- Alert severity classification
- Streamlit dashboard with auto-refresh
- Localhost filtering option
- Safe handling of empty files & permissions  

---

##  System Architecture

```
Real Network Activity
        |
        v
real_time_collector.py
        |
        v
data/network_events.csv
        |
        v
pipeline.py + detector.py
        |
        v
Streamlit Dashboard (Alerts + Graphs)
```

---

##  Event Schema

```
timestamp,user_id,source_ip,destination_ip,protocol,action,bytes_sent,bytes_received
```

---

##  Collector Backends

### 1. psutil
- Reads active network connections
- Easy to use (no special setup)
- Best for demos

### 2. scapy
- Packet-level capture
- Requires:
  - Admin privileges
  - Npcap installed
  - Active network traffic

---

##  Repository Structure

```
.
|-- README.md
|-- requirements.txt
|-- dashboard.py
|-- real_time_collector.py
|-- run_demo.py
|-- docs/
|   `-- project-plan.md
|-- scripts/
|   `-- generate_sample_data.py
`-- src/
    `-- insider_threat_detection/
        |-- __init__.py
        |-- config.py
        |-- detector.py
        |-- models.py
        |-- pipeline.py
        |-- real_time_collector.py
        `-- simulator.py
```

---

##  Quick Start

### 1. Create Virtual Environment
```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. Install Dependencies

```powershell
python -m pip install -r requirements.txt
```

### 3. Run Dashboard

```powershell
streamlit run dashboard.py
```

---

##  Dashboard Features

* Total processed events & alert rate
* Severity levels (Low, Medium, High, Critical)
* Alert timeline
* Alert counts per user
* Traffic volume over time
* Average anomaly score by hour
* Common alert reasons
* Recent alerts
* Full event stream
* CSV export for alerts and data

---

##  Live Demo Setup

In the dashboard sidebar:

* Enable **Run real-time collector**
* Select backend: `psutil` or `scapy`
* Enable **Auto-refresh**
* Adjust refresh interval

---

##  Run Collector Manually

### psutil (recommended)

```powershell
python real_time_collector.py --backend psutil
```

### scapy

```powershell
python real_time_collector.py --backend scapy
```

### Include localhost traffic

```powershell
python real_time_collector.py --backend psutil --include-localhost
```

---

##  Detection Strategy

The baseline model builds **behavior profiles per user** using:

* Typical activity hours
* Known source IPs
* Known destination IPs
* Average bytes sent/received
* Event frequency

An event gets a higher anomaly score when it deviates from these patterns.

Alerts are triggered when the score crosses a threshold.

---

##  Windows Notes

* Run PowerShell as Administrator for better results
* Install **Npcap** for Scapy
* If no events appear:
  * Open a browser or generate traffic
* If permission issues occur:
  * Use `psutil` backend first

---

##  Future Improvements

* Persistent user profiles
* Role-based anomaly thresholds
* Isolation Forest / ML-based detection
* Sliding time window analysis
* Database storage (SQLite/PostgreSQL)
* Process-level enrichment (PID, app name)
* Dashboard threshold tuning
* Compare psutil vs scapy false positives

---


##  Summary

This project is a **real-time insider threat detection prototype** that:

* Collects live network activity
* Builds behavioral baselines
* Detects anomalies
* Generates alerts
* Visualizes everything in real time
