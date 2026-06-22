from __future__ import annotations

import argparse
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TEST_SITE_PATH = PROJECT_ROOT / "Test Site"


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve the local Test Site for client PCs.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    args = parser.parse_args()

    handler = partial(SimpleHTTPRequestHandler, directory=str(TEST_SITE_PATH))
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"Serving Test Site at http://{args.host}:{args.port}")
    print(f"Directory: {TEST_SITE_PATH}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("Test Site server stopped.")


if __name__ == "__main__":
    main()
