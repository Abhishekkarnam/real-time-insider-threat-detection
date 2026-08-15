```markdown
# AI With Firewall VPN Trail

Tailscale/VPN-enabled version of the AI firewall project. This version supports live client log collection over a private Tailscale network, Autoencoder-based anomaly detection, autonomous firewall enforcement, and protected test-site blocking.

## Overview

This project demonstrates an AI-powered insider threat detection and firewall system across multiple PCs connected through Tailscale VPN.

Tailscale provides the private network path. The AI firewall system performs:

- Live event collection
- Behavioral anomaly detection
- Autoencoder Neural Network inference
- AI firewall action selection
- Autonomous block/quarantine enforcement
- Dashboard visualization
- Protected test-site access control

## VPN Architecture

```text
Client 1 PC
  ↓
Tailscale VPN
  ↓
Server PC
  ├── FastAPI Backend :8001
  ├── React Dashboard :5173
  └── Protected Test Site :8080

Client 2 PC
  ↓
Tailscale VPN
  ↓
Server PC
```

## System Flow

```text
Client PC accesses Test Site
↓
client_logger.py sends event to backend
↓
Backend stores event in data/real_time_stored_data.csv
↓
Detection Pipeline + Autoencoder NN analyzes behavior
↓
AI Firewall Advisor selects action
↓
Backend auto-applies strong block/quarantine decisions
↓
data/firewall_rules.csv is updated
↓
Test Site blocks matching client IP
```

## Main Components

```text
backend/app.py
FastAPI backend, API endpoints, autonomous firewall enforcement, rule expiration.

frontend/
React dashboard for monitoring events, AI decisions, and firewall rules.

scripts/client_logger.py
Client-side logger. Supports TAILSCALE_SERVER_IP environment variable.

scripts/serve_test_site.py
Protected website server with app-level firewall enforcement.

scripts/tailscale_config.py
Helper script to detect/write Tailscale server configuration.

TAILSCALE_SETUP.md
Detailed VPN setup instructions.

src/insider_threat_detection/train_firewall_nn.py
Autoencoder NN training pipeline.

src/insider_threat_detection/ai_firewall_advisor.py
NN/rule-based firewall decision engine.

src/insider_threat_detection/firewall.py
Real/app-enforced firewall rule creation and removal.
```

## Install Tailscale

Install Tailscale on:

```text
Server PC
Client 1 PC
Client 2 PC
```

Login all devices into the same Tailnet.

Get the server Tailscale IP:

```powershell
tailscale ip -4
```

Example:

```text
100.78.66.73
```

## Configure Project For VPN

On the server PC:

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
.venv\Scripts\Activate.ps1
py scripts\tailscale_config.py
```

If automatic detection fails:

```powershell
py scripts\tailscale_config.py --server-ip 100.78.66.73
```

This writes:

```text
frontend/.env.local
data/vpn_config.json
```

## Train Autoencoder NN

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
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
cd "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
.venv\Scripts\Activate.ps1
py -m uvicorn backend.app:app --host 0.0.0.0 --port 8001
```

Check from server:

```powershell
curl http://127.0.0.1:8001/api/health
```

Check over Tailscale:

```powershell
curl http://SERVER_TAILSCALE_IP:8001/api/health
```

## Run Protected Test Site

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
.venv\Scripts\Activate.ps1
py scripts\serve_test_site.py --host 0.0.0.0 --port 8080
```

Open from clients:

```text
http://SERVER_TAILSCALE_IP:8080
```

Example:

```text
http://100.78.66.73:8080
```

## Run Dashboard

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall VPN Trail\frontend"
$env:VITE_API_BASE="http://SERVER_TAILSCALE_IP:8001"
npm install
npm run dev -- --host 0.0.0.0 --port 5173
```

Open:

```text
http://SERVER_TAILSCALE_IP:5173
```

Example:

```text
http://100.78.66.73:5173
```

Do not open:

```text
http://0.0.0.0:5173
```

`0.0.0.0` is only used for binding the server.

## Run Client 1 Logger

On Client 1:

```cmd
cd /d "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
set TAILSCALE_SERVER_IP=100.78.66.73
py scripts\client_logger.py --client-id client1 --probe-test-site
```

## Run Client 2 Logger

On Client 2:

```cmd
cd /d "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
set TAILSCALE_SERVER_IP=100.78.66.73
py scripts\client_logger.py --client-id client2 --probe-test-site
```

## Client Browser Access

Each client should open:

```text
http://SERVER_TAILSCALE_IP:8080
```

Dashboard:

```text
http://SERVER_TAILSCALE_IP:5173
```

## Autonomous AI Firewall Enforcement

The AI now auto-applies strong decisions.

Auto-enforcement happens when:

```text
action = quarantine
or confidence >= 0.90
or severity = Critical
or anomaly score >= 4.0
or test-site block confidence >= 0.90
```

Example:

```text
Client accesses protected site outside 8 AM to 5 PM
↓
AI recommends block with 95% confidence
↓
Backend automatically creates firewall rule
↓
Client is blocked from test site
```

No manual Approve click is needed for high-confidence block/quarantine decisions.

## Firewall Rule File

Created automatically after the first block/quarantine:

```text
data/firewall_rules.csv
```

The test site reads this file and blocks active clients with HTTP 403.

## Dashboard

The React dashboard shows:

- Events processed
- Alerts raised
- Critical alerts
- Average behavior score
- Live event stream
- AI decisions
- Auto Applied status
- Active firewall rules
- Unblock button

Auto-applied firewall actions show:

```text
Auto Applied
```

Manual pending actions show:

```text
Pending Review
```

## Windows Firewall Allow Rules

Run once on the server in Administrator CMD if clients cannot connect:

```cmd
netsh advfirewall firewall add rule name="AI Backend 8001 Tailscale" dir=in action=allow protocol=TCP localport=8001
netsh advfirewall firewall add rule name="AI Dashboard 5173 Tailscale" dir=in action=allow protocol=TCP localport=5173
netsh advfirewall firewall add rule name="AI Test Site 8080 Tailscale" dir=in action=allow protocol=TCP localport=8080
```

## Tailscale Notes

Windows may show:

```text
Tailscale: No internet access
```

This is normal. Tailscale is a private VPN adapter, not your main internet gateway.

Test connectivity:

```cmd
tailscale status
ping SERVER_TAILSCALE_IP
curl http://SERVER_TAILSCALE_IP:8001/api/health
curl http://SERVER_TAILSCALE_IP:8080
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

1. Server Tailscale IP is visible:

```powershell
tailscale ip -4
```

2. Backend health works locally:

```powershell
curl http://127.0.0.1:8001/api/health
```

3. Backend health works over VPN:

```powershell
curl http://SERVER_TAILSCALE_IP:8001/api/health
```

4. Test site opens locally:

```text
http://localhost:8080
```

5. Test site opens over VPN:

```text
http://SERVER_TAILSCALE_IP:8080
```

6. Dashboard opens over VPN:

```text
http://SERVER_TAILSCALE_IP:5173
```

7. Client logger uploads events.

8. Dashboard shows live events.

9. AI decision appears.

10. Strong block/quarantine creates:

```text
data/firewall_rules.csv
```

11. Blocked client receives:

```text
403 Access blocked
```

## Notes

- Use the Tailscale server IP from clients.
- Use `localhost` only on the server PC.
- Dashboard refreshes every 1 minute.
- Client timestamps are generated on client PCs.
- Live data is stored in `data/real_time_stored_data.csv`.
- Active firewall rules are stored in `data/firewall_rules.csv`.
```
