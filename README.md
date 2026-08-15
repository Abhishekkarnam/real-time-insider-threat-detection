```markdown
# AI With Firewall

Real-time insider threat detection system with live client log collection, Autoencoder-based anomaly detection, autonomous AI firewall enforcement, and a React security dashboard.

## Overview

This project detects suspicious insider activity by collecting live network access logs from client PCs, scoring behavior, and applying firewall actions when high-risk activity is detected.

The system supports:

- Live client log collection
- FastAPI backend
- React dashboard
- Autoencoder Neural Network anomaly detection
- AI Firewall Advisor
- Autonomous block/quarantine enforcement
- Application-level protected test-site blocking
- Real Windows Firewall / Linux UFW rule attempt
- Automatic firewall rule expiration

## Architecture

```text
Client PC
  ↓
client_logger.py
  ↓
FastAPI Backend
  ↓
data/real_time_stored_data.csv
  ↓
Detection Pipeline + Autoencoder NN
  ↓
AI Firewall Advisor
  ↓
Autonomous Firewall Rule Creation
  ↓
data/firewall_rules.csv
  ↓
Protected Test Site / OS Firewall
```

## Main Components

```text
backend/app.py
FastAPI backend, live API endpoints, collector control, autonomous firewall enforcement, rule expiration.

frontend/
React dashboard for events, alerts, AI decisions, active firewall rules, and unblock actions.

scripts/client_logger.py
Runs on client PCs and sends real access logs to the backend.

scripts/serve_test_site.py
Runs the protected test website and blocks clients listed in firewall_rules.csv.

src/insider_threat_detection/train_firewall_nn.py
Trains the Autoencoder Neural Network.

src/insider_threat_detection/ai_firewall_advisor.py
Uses rule logic and NN reconstruction error to recommend allow, monitor, block, or quarantine.

src/insider_threat_detection/firewall.py
Applies real/app-enforced firewall rules and manages rule storage.
```

## Dataset

Default training dataset:

```text
train_test_network.csv
```

Train the model:

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall"
.venv\Scripts\Activate.ps1
py -m pip install -r requirements.txt
py -m pip install -e .
py -m insider_threat_detection.train_firewall_nn
```

Model outputs:

```text
models/firewall_nn.keras
models/firewall_preprocessor.pkl
```

## Run Backend

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall"
.venv\Scripts\Activate.ps1
py -m uvicorn backend.app:app --host 0.0.0.0 --port 8001
```

Health check:

```powershell
curl http://127.0.0.1:8001/api/health
```

Expected:

```json
{"status":"ok"}
```

## Run Protected Test Site

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall"
.venv\Scripts\Activate.ps1
py scripts\serve_test_site.py --host 0.0.0.0 --port 8080
```

Open on server:

```text
http://localhost:8080
```

Open from clients:

```text
http://SERVER_IP:8080
```

## Run Frontend Dashboard

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall\frontend"
$env:VITE_API_BASE="http://127.0.0.1:8001"
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

Open:

```text
http://localhost:5173
```

If opening from another PC on the same network:

```text
http://SERVER_IP:5173
```

Then start frontend with:

```powershell
$env:VITE_API_BASE="http://SERVER_IP:8001"
npm run dev -- --host 0.0.0.0 --port 5173
```

## Run Client Logger

On Client 1:

```cmd
cd /d "C:\SEM 6\Network Security\AI With Firewall"
py scripts\client_logger.py --server-api http://SERVER_IP:8001/api/events --test-site-host SERVER_IP --test-site-port 8080 --client-id client1 --probe-test-site
```

On Client 2:

```cmd
cd /d "C:\SEM 6\Network Security\AI With Firewall"
py scripts\client_logger.py --server-api http://SERVER_IP:8001/api/events --test-site-host SERVER_IP --test-site-port 8080 --client-id client2 --probe-test-site
```

Replace:

```text
SERVER_IP
```

with the server PC IP address.

Example:

```text
192.168.20.86
```

## Autonomous AI Firewall Enforcement

The backend automatically applies strong AI decisions.

Auto-enforcement happens when:

```text
action = quarantine
or confidence >= 0.90
or severity = Critical
or anomaly score >= 4.0
or test-site block confidence >= 0.90
```

Flow:

```text
Client event received
↓
Detector + NN analyzes behavior
↓
AI Firewall Advisor recommends block/quarantine
↓
Backend automatically calls apply_rule()
↓
firewall_rules.csv is created/updated
↓
Test site blocks the client
```

No dashboard approval is required for high-confidence block/quarantine actions.

Lower-risk decisions remain pending and can still be reviewed manually.

## Firewall Rule File

Created automatically after the first block/quarantine:

```text
data/firewall_rules.csv
```

The protected test site reads this file and returns HTTP 403 to blocked clients.

## Dashboard Behavior

The dashboard shows:

- Events processed
- Alerts raised
- Critical alerts
- Average risk score
- Live event stream
- AI decisions
- Auto Applied badges
- Active firewall rules
- Unblock button

Auto-applied decisions do not show Approve/Reject buttons. Use the Unblock button under Active Firewall Rules to restore access.

## Time-Based Test-Site Policy

Protected test-site access between:

```text
8 AM to 5 PM
```

is treated as normal/monitoring behavior.

Access outside:

```text
8 AM to 5 PM
```

is treated as suspicious and can be auto-blocked.

## Windows Firewall Notes

Real Windows Firewall rules require Administrator permission.

If OS-level firewall commands fail, the system falls back to application-level enforcement through the test-site server.

Allow ports if needed from Administrator CMD:

```cmd
netsh advfirewall firewall add rule name="AI Backend 8001" dir=in action=allow protocol=TCP localport=8001
netsh advfirewall firewall add rule name="AI Dashboard 5173" dir=in action=allow protocol=TCP localport=5173
netsh advfirewall firewall add rule name="AI Test Site 8080" dir=in action=allow protocol=TCP localport=8080
```

## API Endpoints

```text
GET  /api/health
GET  /api/summary
GET  /api/events
GET  /api/alerts
GET  /api/firewall/recommendations
GET  /api/firewall/rules
POST /api/firewall/approve
POST /api/firewall/reject
POST /api/firewall/unblock
POST /api/collector/start
POST /api/collector/stop
POST /api/events
```

## Testing Checklist

1. Backend health works:

```powershell
curl http://127.0.0.1:8001/api/health
```

2. Test site opens:

```text
http://localhost:8080
```

3. Dashboard opens:

```text
http://localhost:5173
```

4. Client can reach server:

```cmd
ping SERVER_IP
curl http://SERVER_IP:8001/api/health
curl http://SERVER_IP:8080
```

5. Client logger uploads events.

6. Dashboard shows live events.

7. AI decision appears.

8. Strong block/quarantine decision creates:

```text
data/firewall_rules.csv
```

9. Blocked client receives:

```text
403 Access blocked
```

## Notes

- Dashboard refreshes every 1 minute.
- Client timestamps are generated on the client PC.
- Live data is stored in `data/real_time_stored_data.csv`.
- Firewall rules are stored in `data/firewall_rules.csv`.
- Firewall rules expire automatically based on `duration_minutes`.
```
