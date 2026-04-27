from __future__ import annotations

import argparse
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from insider_threat_detection.real_time_collector import (  # noqa: E402
    collect_and_append_events,
)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Collect real-time network events into the project CSV.")
    parser.add_argument("--backend", choices=["psutil", "scapy"], default="psutil")
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--include-localhost", action="store_true")
    args = parser.parse_args()

    try:
        collect_and_append_events(
            PROJECT_ROOT / "data" / "network_events.csv",
            interval_seconds=args.interval,
            ignore_localhost=not args.include_localhost,
            backend=args.backend,
        )
    except KeyboardInterrupt:
        print("Stopped real-time network collector.")
