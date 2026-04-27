Real-Time Insider Threat Detection Using Network Behavior Profiling
This project detects suspicious insider activity by collecting live system/network activity, building behavior profiles for users, scoring deviations, and displaying alerts in a Streamlit dashboard.

The original starter version used simulated CSV data. The current version supports real-time collection from the local Windows machine using psutil or packet capture with scapy.

Project Idea
Insider threats are difficult to detect because the user may already have valid access. Instead of relying only on signatures or blocklists, this project learns normal behavior patterns and raises alerts when current activity deviates from that baseline.

Examples of suspicious behavior include:

Connecting to rarely used destinations
Sudden spikes in upload/download volume
Abnormal access frequency
New source IP or device-like changes
Network activity at unusual hours
Current Scope
The current project includes:

Real-time network collection using psutil
Optional packet-level capture using scapy
Continuous append-only CSV event storage
CSV compatibility with the existing anomaly pipeline
Per-user behavior profiling
Lightweight anomaly scoring
Alert severity classification
Streamlit dashboard with auto-refresh
Optional localhost traffic filtering
Safe handling for empty files, permissions, and partial CSV reads
How The System Works
real network activity
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
Streamlit dashboard alerts and charts
The collector appends live events to data/network_events.csv. The dashboard continuously reads that CSV, sends events through the anomaly detection pipeline, and displays scored events and alerts.

Event Schema
The CSV uses this schema:

timestamp,user_id,source_ip,destination_ip,protocol,action,bytes_sent,bytes_received
This keeps the real-time collector compatible with the existing detection pipeline.

Collector Backends
psutil
psutil reads active network connections from the operating system.

Use this backend for normal Windows demos because it is simpler and usually does not require packet-capture drivers.

scapy
scapy captures packets directly.

Use this backend when you want packet-level visibility. On Windows, Scapy usually requires:

Administrator PowerShell or terminal
Npcap installed
Active network traffic during capture
Repository Structure
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
simulator.py and scripts/generate_sample_data.py are kept as optional legacy/sample-data helpers. The main project path now uses real-time collection.

Quick Start
Create and activate a virtual environment:

python -m venv .venv
.venv\Scripts\Activate.ps1
Install dependencies:

python -m pip install -r requirements.txt
Run the dashboard:

streamlit run dashboard.py
In the dashboard sidebar:

Turn on Run real-time collector
Choose psutil or scapy as the collector backend
Keep Ignore localhost traffic enabled unless you want loopback events
Turn on Auto-refresh dashboard to watch new events appear
Running The Collector Directly
Run the default psutil collector:

python real_time_collector.py --backend psutil
Run the Scapy packet-capture collector:

python real_time_collector.py --backend scapy
Include localhost traffic if needed:

python real_time_collector.py --backend psutil --include-localhost
The collector appends events every 5 seconds by default.

Dashboard
The Streamlit dashboard shows:

Total processed events and alert rate
Severity overview with Low, Medium, High, and Critical alerts
Alert timeline
Alert counts by user
Traffic volume over time
Average anomaly score by hour
Common alert reasons
Recent alerts
Full scored event stream
Downloadable CSV exports for alerts and scored events
Current Detection Strategy
The baseline detector uses lightweight behavior profiling:

Typical activity hour per user
Known source IPs
Known destination IPs
Average bytes sent
Average bytes received
Recent event frequency
An event receives a higher score when it contains multiple deviations from the user's normal profile. Alerts are generated when the score crosses the configured threshold.

Windows Notes
Run PowerShell as Administrator for better network visibility.
Scapy packet capture may require Npcap.
If no events appear, open a browser or another networked application and refresh the dashboard.
If permission errors appear, use the psutil backend first, then try Scapy with Administrator privileges.
Good Next Steps
Add persistent user profiles instead of rebuilding profiles from CSV each run
Add role-based anomaly thresholds
Train an unsupervised model such as Isolation Forest
Use sliding time windows for behavior profiles
Store events and alerts in SQLite or PostgreSQL
Add process name and PID enrichment for psutil events
Add dashboard controls for alert threshold tuning
Compare false positives between psutil and scapy backends
Course Report Sections
Problem statement
Literature review
Dataset and feature design
Real-time collection methodology
Behavior profiling methodology
Detection and alerting strategy
Experimental results
Limitations and future work
This project is now a real-time insider threat detection prototype that can collect live network activity, append it to the existing CSV pipeline, score anomalies, and visualize alerts through Streamlit.
