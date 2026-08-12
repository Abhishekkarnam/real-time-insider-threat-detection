r"""Create local Tailscale run configuration for the AI firewall demo.

Run this on the server PC after installing and logging in to Tailscale:

    py scripts\tailscale_config.py

Or pass the server Tailscale IP manually:

    py scripts\tailscale_config.py --server-ip 100.x.x.x

The script writes:
    - frontend\.env.local
    - data\vpn_config.json

It does not install Tailscale or change firewall rules.
"""

from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
FRONTEND_ENV_PATH = PROJECT_ROOT / "frontend" / ".env.local"
VPN_CONFIG_PATH = PROJECT_ROOT / "data" / "vpn_config.json"


def detect_tailscale_ip() -> str:
    try:
        result = subprocess.run(
            ["tailscale", "ip", "-4"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""

    if result.returncode != 0:
        return ""

    for line in result.stdout.splitlines():
        candidate = line.strip()
        if candidate.startswith("100."):
            return candidate
    return ""


def write_config(server_ip: str, backend_port: int, dashboard_port: int, test_site_port: int) -> None:
    VPN_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    FRONTEND_ENV_PATH.parent.mkdir(parents=True, exist_ok=True)

    FRONTEND_ENV_PATH.write_text(
        f"VITE_API_BASE=http://{server_ip}:{backend_port}\n",
        encoding="utf-8",
    )
    VPN_CONFIG_PATH.write_text(
        json.dumps(
            {
                "server_tailscale_ip": server_ip,
                "backend_url": f"http://{server_ip}:{backend_port}",
                "dashboard_url": f"http://{server_ip}:{dashboard_port}",
                "test_site_url": f"http://{server_ip}:{test_site_port}",
                "client_events_api": f"http://{server_ip}:{backend_port}/api/events",
                "updated_at": datetime.now().replace(microsecond=0).isoformat(),
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepare this project folder for a Tailscale VPN demo.")
    parser.add_argument("--server-ip", default="", help="Server PC Tailscale IPv4 address, usually 100.x.x.x")
    parser.add_argument("--backend-port", type=int, default=8001)
    parser.add_argument("--dashboard-port", type=int, default=5173)
    parser.add_argument("--test-site-port", type=int, default=8080)
    args = parser.parse_args()

    server_ip = args.server_ip.strip() or detect_tailscale_ip()
    if not server_ip:
        raise SystemExit("Could not detect Tailscale IP. Run `tailscale ip -4` or pass --server-ip 100.x.x.x")

    write_config(server_ip, args.backend_port, args.dashboard_port, args.test_site_port)

    print("Tailscale config written.")
    print(f"Server Tailscale IP: {server_ip}")
    print(f"Backend:   http://{server_ip}:{args.backend_port}")
    print(f"Dashboard: http://{server_ip}:{args.dashboard_port}")
    print(f"Test site: http://{server_ip}:{args.test_site_port}")
    print("")
    print("Server commands:")
    print(f"  py -m uvicorn backend.app:app --host 0.0.0.0 --port {args.backend_port}")
    print(f"  py scripts\\serve_test_site.py --host 0.0.0.0 --port {args.test_site_port}")
    print(f"  cd frontend")
    print(f"  npm run dev -- --host 0.0.0.0 --port {args.dashboard_port}")
    print("")
    print("Client logger command:")
    print(f"  set TAILSCALE_SERVER_IP={server_ip}")
    print("  py scripts\\client_logger.py --client-id client1 --probe-test-site")


if __name__ == "__main__":
    main()
