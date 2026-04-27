from __future__ import annotations

import csv
import getpass
import ipaddress
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

try:
    import psutil
except ImportError:
    psutil = None

try:
    from scapy.all import ICMP, IP, TCP, UDP, sniff
except ImportError:
    ICMP = IP = TCP = UDP = sniff = None


FIELDNAMES = [
    "timestamp",
    "user_id",
    "source_ip",
    "destination_ip",
    "protocol",
    "action",
    "bytes_sent",
    "bytes_received",
]

DEFAULT_DATA_PATH = Path(__file__).resolve().parents[2] / "data" / "network_events.csv"
COLLECTION_INTERVAL_SECONDS = 5

_csv_lock = threading.Lock()
_collector_lock = threading.Lock()
_collector_thread: threading.Thread | None = None
_collector_stop_event: threading.Event | None = None
_collector_config: tuple[Path, int, bool, str] | None = None
_seen_connections: set[tuple[object, ...]] = set()
_last_io_counters: Any | None = None


def is_psutil_available() -> bool:
    return psutil is not None


def is_scapy_available() -> bool:
    return sniff is not None and IP is not None


def ensure_events_file(csv_path: Path = DEFAULT_DATA_PATH) -> None:
    csv_path.parent.mkdir(parents=True, exist_ok=True)
    if csv_path.exists() and csv_path.stat().st_size > 0:
        return

    with _csv_lock:
        if csv_path.exists() and csv_path.stat().st_size > 0:
            return
        with csv_path.open("w", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
            writer.writeheader()


def _address_ip(address: object) -> str:
    if not address:
        return ""
    return str(getattr(address, "ip", "") or address[0])


def _address_port(address: object) -> int | None:
    if not address:
        return None
    return getattr(address, "port", None) or int(address[1])


def _is_loopback(ip_address: str) -> bool:
    try:
        return ipaddress.ip_address(ip_address).is_loopback
    except ValueError:
        return ip_address.lower() == "localhost"


def _protocol_from_type(connection_type: int) -> str:
    if connection_type == socket.SOCK_STREAM:
        return "TCP"
    if connection_type == socket.SOCK_DGRAM:
        return "UDP"
    return "UNKNOWN"


def _protocol_from_packet(packet: Any) -> str:
    if TCP is not None and packet.haslayer(TCP):
        return "TCP"
    if UDP is not None and packet.haslayer(UDP):
        return "UDP"
    if ICMP is not None and packet.haslayer(ICMP):
        return "ICMP"
    return "IP"


def _action_from_status(status: str) -> str:
    normalized = (status or "").lower()
    if normalized == "established":
        return "network_connection"
    if normalized == "listen":
        return "listening_socket"
    if normalized:
        return f"connection_{normalized}"
    return "network_activity"


def _username_for_pid(pid: int | None) -> str:
    if psutil is None:
        return getpass.getuser()
    if pid is None:
        return getpass.getuser()

    try:
        username = psutil.Process(pid).username()
    except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
        return getpass.getuser()

    return username or getpass.getuser()


def _connection_signature(connection: Any) -> tuple[object, ...]:
    return (
        connection.pid,
        _address_ip(connection.laddr),
        _address_port(connection.laddr),
        _address_ip(connection.raddr),
        _address_port(connection.raddr),
        connection.type,
        connection.status,
    )


def _bytes_delta() -> tuple[int, int]:
    global _last_io_counters

    if psutil is None:
        return 0, 0

    try:
        counters = psutil.net_io_counters()
    except (psutil.Error, OSError):
        return 0, 0

    if _last_io_counters is None:
        _last_io_counters = counters
        return 0, 0

    sent_delta = max(0, counters.bytes_sent - _last_io_counters.bytes_sent)
    received_delta = max(0, counters.bytes_recv - _last_io_counters.bytes_recv)
    _last_io_counters = counters
    return sent_delta, received_delta


def _local_ip_addresses() -> set[str]:
    addresses: set[str] = set()

    try:
        hostname = socket.gethostname()
        addresses.update(socket.gethostbyname_ex(hostname)[2])
    except OSError:
        pass

    if psutil is None:
        return addresses

    try:
        for interface_addresses in psutil.net_if_addrs().values():
            for address in interface_addresses:
                if address.family in {socket.AF_INET, socket.AF_INET6}:
                    addresses.add(str(address.address).split("%", maxsplit=1)[0])
    except (psutil.Error, OSError):
        pass

    return addresses


def _append_rows(csv_path: Path, rows: list[dict[str, str | int]]) -> int:
    if not rows:
        return 0

    with _csv_lock:
        ensure_events_file(csv_path)
        with csv_path.open("a", newline="", encoding="utf-8") as file:
            writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
            writer.writerows(rows)

    return len(rows)


def _build_rows(
    connections: Iterable[Any],
    ignore_localhost: bool,
) -> list[dict[str, str | int]]:
    new_connections: list[Any] = []

    for connection in connections:
        source_ip = _address_ip(connection.laddr)
        destination_ip = _address_ip(connection.raddr)

        if not source_ip or not destination_ip:
            continue
        if ignore_localhost and (_is_loopback(source_ip) or _is_loopback(destination_ip)):
            continue

        signature = _connection_signature(connection)
        if signature in _seen_connections:
            continue

        _seen_connections.add(signature)
        new_connections.append(connection)

    if not new_connections:
        return []

    sent_delta, received_delta = _bytes_delta()
    bytes_sent = sent_delta // len(new_connections) if sent_delta else 0
    bytes_received = received_delta // len(new_connections) if received_delta else 0
    captured_at = datetime.now().replace(microsecond=0).isoformat()

    return [
        {
            "timestamp": captured_at,
            "user_id": _username_for_pid(connection.pid),
            "source_ip": _address_ip(connection.laddr),
            "destination_ip": _address_ip(connection.raddr),
            "protocol": _protocol_from_type(connection.type),
            "action": _action_from_status(connection.status),
            "bytes_sent": bytes_sent,
            "bytes_received": bytes_received,
        }
        for connection in new_connections
    ]


def _collect_once_psutil(
    csv_path: Path = DEFAULT_DATA_PATH,
    ignore_localhost: bool = True,
) -> int:
    if psutil is None:
        print("psutil is not installed. Run `python -m pip install -r requirements.txt`.")
        return 0

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as error:
        print(
            "Permission denied while reading network connections. "
            "Run PowerShell as Administrator for complete visibility. "
            f"Details: {error}"
        )
        return 0
    except (psutil.Error, OSError) as error:
        print(f"Unable to read network connections safely: {error}")
        return 0

    rows = _build_rows(connections, ignore_localhost=ignore_localhost)
    return _append_rows(csv_path, rows)


def _build_packet_rows(
    packets: Iterable[Any],
    ignore_localhost: bool,
) -> list[dict[str, str | int]]:
    local_ips = _local_ip_addresses()
    current_user = getpass.getuser()
    rows: list[dict[str, str | int]] = []

    for packet in packets:
        if IP is None or not packet.haslayer(IP):
            continue

        ip_layer = packet[IP]
        source_ip = str(ip_layer.src)
        destination_ip = str(ip_layer.dst)

        if ignore_localhost and (_is_loopback(source_ip) or _is_loopback(destination_ip)):
            continue

        packet_size = len(packet)
        is_outbound = source_ip in local_ips
        captured_at = datetime.fromtimestamp(float(packet.time)).replace(microsecond=0).isoformat()

        rows.append(
            {
                "timestamp": captured_at,
                "user_id": current_user,
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "protocol": _protocol_from_packet(packet),
                "action": "packet_capture",
                "bytes_sent": packet_size if is_outbound else 0,
                "bytes_received": 0 if is_outbound else packet_size,
            }
        )

    return rows


def _collect_once_scapy(
    csv_path: Path = DEFAULT_DATA_PATH,
    ignore_localhost: bool = True,
    capture_seconds: int = COLLECTION_INTERVAL_SECONDS,
) -> int:
    if sniff is None:
        print("scapy is not installed. Run `python -m pip install -r requirements.txt`.")
        return 0

    try:
        packets = sniff(filter="ip", timeout=capture_seconds, store=True)
    except PermissionError as error:
        print(
            "Permission denied while capturing packets. "
            "Run PowerShell as Administrator and make sure Npcap is installed. "
            f"Details: {error}"
        )
        return 0
    except OSError as error:
        print(
            "Unable to capture packets with Scapy. On Windows, install Npcap "
            f"and run as Administrator. Details: {error}"
        )
        return 0
    except Exception as error:
        print(f"Unable to capture packets safely with Scapy: {error}")
        return 0

    rows = _build_packet_rows(packets, ignore_localhost=ignore_localhost)
    return _append_rows(csv_path, rows)


def collect_once(
    csv_path: Path = DEFAULT_DATA_PATH,
    ignore_localhost: bool = True,
    backend: str = "psutil",
    capture_seconds: int = COLLECTION_INTERVAL_SECONDS,
) -> int:
    ensure_events_file(csv_path)

    if backend == "scapy":
        return _collect_once_scapy(
            csv_path=csv_path,
            ignore_localhost=ignore_localhost,
            capture_seconds=capture_seconds,
        )

    return _collect_once_psutil(csv_path=csv_path, ignore_localhost=ignore_localhost)


def collect_and_append_events(
    csv_path: Path = DEFAULT_DATA_PATH,
    interval_seconds: int = COLLECTION_INTERVAL_SECONDS,
    ignore_localhost: bool = True,
    backend: str = "psutil",
    stop_event: threading.Event | None = None,
) -> None:
    ensure_events_file(csv_path)

    while stop_event is None or not stop_event.is_set():
        collect_once(
            csv_path=csv_path,
            ignore_localhost=ignore_localhost,
            backend=backend,
            capture_seconds=interval_seconds,
        )

        if backend == "scapy":
            continue
        if stop_event is None:
            time.sleep(interval_seconds)
        else:
            stop_event.wait(interval_seconds)


def start_background_collector(
    csv_path: Path = DEFAULT_DATA_PATH,
    interval_seconds: int = COLLECTION_INTERVAL_SECONDS,
    ignore_localhost: bool = True,
    backend: str = "psutil",
) -> bool:
    global _collector_config, _collector_stop_event, _collector_thread

    with _collector_lock:
        requested_config = (csv_path, interval_seconds, ignore_localhost, backend)
        if _collector_thread is not None and _collector_thread.is_alive():
            if _collector_config == requested_config:
                return False
            if _collector_stop_event is not None:
                _collector_stop_event.set()
            _collector_thread.join(timeout=2)
            if _collector_thread.is_alive():
                return False

        _collector_stop_event = threading.Event()
        _collector_config = requested_config
        _collector_thread = threading.Thread(
            target=collect_and_append_events,
            kwargs={
                "csv_path": csv_path,
                "interval_seconds": interval_seconds,
                "ignore_localhost": ignore_localhost,
                "backend": backend,
                "stop_event": _collector_stop_event,
            },
            daemon=True,
            name="insider-threat-real-time-collector",
        )
        _collector_thread.start()
        return True


def stop_background_collector() -> bool:
    global _collector_config, _collector_stop_event

    with _collector_lock:
        if _collector_thread is None or not _collector_thread.is_alive():
            return False
        if _collector_stop_event is not None:
            _collector_stop_event.set()
        _collector_config = None
        return True


def is_background_collector_running() -> bool:
    return _collector_thread is not None and _collector_thread.is_alive()


if __name__ == "__main__":
    try:
        collect_and_append_events()
    except KeyboardInterrupt:
        print("Stopped real-time network collector.")
