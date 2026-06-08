from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parent
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from insider_threat_detection.real_time_collector import (  # noqa: E402
    DEFAULT_DATA_PATH,
    FIELDNAMES,
    _append_rows,
    ensure_events_file,
)


def _valid_event(row: dict[str, Any]) -> bool:
    return all(field in row and row[field] not in (None, "") for field in FIELDNAMES)


def _normalize_event(row: dict[str, Any]) -> dict[str, str | int]:
    return {
        "timestamp": str(row["timestamp"]),
        "user_id": str(row["user_id"]),
        "source_ip": str(row["source_ip"]),
        "destination_ip": str(row["destination_ip"]),
        "protocol": str(row["protocol"]),
        "action": str(row["action"]),
        "bytes_sent": int(row["bytes_sent"]),
        "bytes_received": int(row["bytes_received"]),
    }


class EventReceiverHandler(BaseHTTPRequestHandler):
    csv_path = DEFAULT_DATA_PATH

    def _send_json(self, status_code: int, payload: dict[str, object]) -> None:
        response = json.dumps(payload).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(200, {"status": "ok"})
            return
        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path != "/events":
            self._send_json(404, {"error": "not found"})
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
            payload = json.loads(self.rfile.read(content_length).decode("utf-8"))
            raw_events = payload.get("events", [])
        except (ValueError, json.JSONDecodeError):
            self._send_json(400, {"error": "invalid json"})
            return

        if not isinstance(raw_events, list):
            self._send_json(400, {"error": "events must be a list"})
            return

        rows: list[dict[str, str | int]] = []
        for row in raw_events:
            if isinstance(row, dict) and _valid_event(row):
                try:
                    rows.append(_normalize_event(row))
                except (TypeError, ValueError):
                    continue

        accepted = _append_rows(self.csv_path, rows)
        self._send_json(200, {"accepted": accepted})

    def log_message(self, format: str, *args: object) -> None:
        print(f"{self.address_string()} - {format % args}")


def run_server(host: str, port: int, csv_path: Path) -> None:
    ensure_events_file(csv_path)
    EventReceiverHandler.csv_path = csv_path
    server = ThreadingHTTPServer((host, port), EventReceiverHandler)
    print(f"Collector server listening on http://{host}:{port}")
    print(f"Writing received events to {csv_path}")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Receive network events from client PCs.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5050)
    parser.add_argument("--csv-path", type=Path, default=PROJECT_ROOT / "data" / "network_events.csv")
    args = parser.parse_args()

    try:
        run_server(args.host, args.port, args.csv_path)
    except KeyboardInterrupt:
        print("Stopped collector server.")
