# Tailscale VPN Setup For AI Firewall Demo

Use Tailscale to place the server PC and two Windows client PCs on the same private VPN. The AI firewall still runs inside this project; Tailscale only provides the secure network path.

## 1. Install And Login

Install Tailscale on:

- Server PC
- Client 1 PC
- Client 2 PC

Login all three devices into the same Tailnet.

## 2. Get The Server Tailscale IP

On the server PC:

```powershell
tailscale ip -4
```

Copy the `100.x.x.x` address. This is the only IP the clients should use.

## 3. Configure This Project Folder

On the server PC:

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
.venv\Scripts\Activate.ps1
py scripts\tailscale_config.py
```

If automatic detection fails:

```powershell
py scripts\tailscale_config.py --server-ip 100.x.x.x
```

This creates:

```text
frontend\.env.local
data\vpn_config.json
```

## 4. Start The Server Components

Terminal 1, backend:

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
.venv\Scripts\Activate.ps1
py -m uvicorn backend.app:app --host 0.0.0.0 --port 8001
```

Terminal 2, protected test site:

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
.venv\Scripts\Activate.ps1
py scripts\serve_test_site.py --host 0.0.0.0 --port 8080
```

Terminal 3, dashboard:

```powershell
cd "C:\SEM 6\Network Security\AI With Firewall VPN Trail\frontend"
npm run dev -- --host 0.0.0.0 --port 5173
```

Open dashboard:

```text
http://SERVER_TAILSCALE_IP:5173
```

Open protected site:

```text
http://SERVER_TAILSCALE_IP:8080
```

## 5. Start Client 1 Logger

On Client 1:

```cmd
cd /d "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
set TAILSCALE_SERVER_IP=100.x.x.x
py scripts\client_logger.py --client-id client1 --probe-test-site
```

## 6. Start Client 2 Logger

On Client 2:

```cmd
cd /d "C:\SEM 6\Network Security\AI With Firewall VPN Trail"
set TAILSCALE_SERVER_IP=100.x.x.x
py scripts\client_logger.py --client-id client2 --probe-test-site
```

## 7. Expected Flow

```text
Client accesses Test Site over Tailscale
client_logger.py creates timestamp on client PC
client_logger.py posts event to FastAPI
FastAPI stores the event in data\real_time_stored_data.csv
Detection pipeline scores the event
Autoencoder advisor recommends monitor/block/quarantine
Dashboard shows pending action
Approve creates firewall_rules.csv entry
Test Site returns 403 to blocked client IP
```

## 8. Windows Firewall Allow Rules

Run these once on the server PC in Administrator Command Prompt if clients cannot connect:

```cmd
netsh advfirewall firewall add rule name="AI Backend 8001 Tailscale" dir=in action=allow protocol=TCP localport=8001
netsh advfirewall firewall add rule name="AI Dashboard 5173 Tailscale" dir=in action=allow protocol=TCP localport=5173
netsh advfirewall firewall add rule name="AI Test Site 8080 Tailscale" dir=in action=allow protocol=TCP localport=8080
```

## 9. Testing

From each client:

```cmd
ping 100.x.x.x
curl http://100.x.x.x:8001/api/health
curl http://100.x.x.x:8080
```

Do not browse to `0.0.0.0`. Use `localhost` only on the server PC, or the `100.x.x.x` Tailscale IP from clients.
