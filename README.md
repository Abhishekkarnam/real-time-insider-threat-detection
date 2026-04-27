# Real-Time Insider Threat Detection Using Network Behavior Profiling

This repository is a starter implementation for a course project focused on detecting insider threats by modeling user network behavior over time and flagging deviations in real time.

## Project Idea

Insider threats are difficult to detect because the attacker is often a legitimate user. Instead of relying only on signatures or blacklists, this project builds a behavior profile for each user and raises alerts when activity becomes unusual.

Examples of suspicious behavior include:

- Logging in at unusual hours
- Connecting to rarely used destinations
- Sudden spikes in upload volume
- Abnormal access frequency
- New device or source IP changes

## Starter Scope

This starter version includes:

- A clean Python project structure
- Synthetic event generation for normal and suspicious traffic
- Real-time per-user behavior profiling
- A simple anomaly scoring engine
- Alert generation for high-risk events
- A Streamlit dashboard for alerts and graphs

## Suggested Final Project Flow

1. Collect or simulate network events
2. Build per-user normal behavior profiles
3. Extract real-time features from each event
4. Score anomalies using behavioral deviation
5. Raise alerts with reasons
6. Evaluate precision, recall, and false positives

## Repository Structure

```text
.
|-- README.md
|-- requirements.txt
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
        `-- simulator.py
```

## Quick Start

1. Create a virtual environment
2. Install requirements
3. Generate sample data
4. Run the pipeline

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python scripts/generate_sample_data.py
python run_demo.py
```

## Dashboard

Launch the Streamlit dashboard with:

```powershell
streamlit run dashboard.py
```

The dashboard shows:

- Total processed events and alert rate
- Severity overview with Low, Medium, High, and Critical alert levels
- Alert timeline
- Alert counts by user
- Traffic volume over time
- Average anomaly score by hour
- Common alert reasons
- Recent alerts and the full scored event stream
- Downloadable CSV export for alerts and scored events

For a live demo experience:

- Turn on `Auto-refresh dashboard`
- Turn on `Live simulation mode`
- Choose a refresh interval and events-per-refresh batch size
- Watch new events and alerts appear automatically

## Current Detection Strategy

The baseline detector uses lightweight behavior profiling:

- Typical login hour range per user
- Known source IPs
- Known destination IPs
- Average bytes sent and received
- Event count growth

It then scores an event higher when it contains multiple deviations from the user's normal profile.

## Good Next Steps

- Add role-based anomaly thresholds and severity levels
- Train an unsupervised model such as Isolation Forest
- Use sliding time windows for richer behavior profiles
- Add role-based baselines across teams
- Compare behavior before and after suspicious events
- Export alerts to CSV or a database

## Course Report Sections

- Problem statement
- Literature review
- Dataset and feature design
- Detection methodology
- Experimental results
- Limitations and future work

This starter is designed to help you begin immediately, then improve the system step by step as your course project grows.
