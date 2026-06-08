from __future__ import annotations

import csv
import getpass
import ipaddress
import json
import re
import socket
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

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
_seen_putty_ports: set[tuple[object, ...]] = set()
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


def _putty_port_action(protocol: str, port: int | str | None, status: str = "") -> str:
    port_text = f"_port_{port}" if port else ""
    status_text = f"_{status.lower()}" if status else ""
    return f"putty_{protocol.lower()}{port_text}{status_text}"


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


def _tag_rows_with_client_id(
    rows: list[dict[str, str | int]],
    client_id: str | None,
) -> list[dict[str, str | int]]:
    if not client_id:
        return rows

    tagged_rows: list[dict[str, str | int]] = []
    for row in rows:
        tagged_row = row.copy()
        tagged_row["user_id"] = f"{client_id}:{tagged_row['user_id']}"
        tagged_rows.append(tagged_row)
    return tagged_rows


def send_rows_to_server(
    server_url: str,
    rows: list[dict[str, str | int]],
    timeout_seconds: int = 5,
) -> int:
    if not rows:
        return 0

    payload = json.dumps({"events": rows}).encode("utf-8")
    request = Request(
        server_url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=timeout_seconds) as response:
            response_body = response.read().decode("utf-8")
    except (HTTPError, URLError, TimeoutError, OSError) as error:
        print(f"Unable to send events to collector server: {error}")
        return 0

    try:
        response_data = json.loads(response_body or "{}")
    except json.JSONDecodeError:
        return len(rows)

    return int(response_data.get("accepted", len(rows)))


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


def _collect_rows_psutil(
    ignore_localhost: bool = True,
) -> list[dict[str, str | int]]:
    if psutil is None:
        print("psutil is not installed. Run `python -m pip install -r requirements.txt`.")
        return []

    try:
        connections = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, PermissionError) as error:
        print(
            "Permission denied while reading network connections. "
            "Run PowerShell as Administrator for complete visibility. "
            f"Details: {error}"
        )
        return []
    except (psutil.Error, OSError) as error:
        print(f"Unable to read network connections safely: {error}")
        return []

    return _build_rows(connections, ignore_localhost=ignore_localhost)


def _putty_serial_port_from_cmdline(cmdline: list[str]) -> str | None:
    normalized = " ".join(cmdline)
    serial_match = re.search(r"(?:-serial\s+)?\b(COM\d+)\b", normalized, flags=re.IGNORECASE)
    if serial_match:
        return serial_match.group(1).upper()
    return None


def _collect_rows_putty(
    ignore_localhost: bool = True,
) -> list[dict[str, str | int]]:
    if psutil is None:
        print("psutil is not installed. Run `python -m pip install -r requirements.txt`.")
        return []

    rows: list[dict[str, str | int]] = []
    captured_at = datetime.now().replace(microsecond=0).isoformat()

    for process in psutil.process_iter(["pid", "name", "username", "cmdline"]):
        try:
            process_name = (process.info.get("name") or "").lower()
            if process_name not in {"putty.exe", "putty"}:
                continue

            pid = int(process.info["pid"])
            user_id = process.info.get("username") or _username_for_pid(pid)
            cmdline = process.info.get("cmdline") or []
            serial_port = _putty_serial_port_from_cmdline(cmdline)

            if serial_port:
                signature = (pid, "serial", serial_port)
                if signature not in _seen_putty_ports:
                    _seen_putty_ports.add(signature)
                    rows.append(
                        {
                            "timestamp": captured_at,
                            "user_id": str(user_id),
                            "source_ip": socket.gethostname(),
                            "destination_ip": serial_port,
                            "protocol": "SERIAL",
                            "action": _putty_port_action("serial", serial_port),
                            "bytes_sent": 0,
                            "bytes_received": 0,
                        }
                    )

            try:
                connections = process.net_connections(kind="inet")
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                connections = []

            for connection in connections:
                source_ip = _address_ip(connection.laddr)
                destination_ip = _address_ip(connection.raddr)
                destination_port = _address_port(connection.raddr)

                if not source_ip or not destination_ip or destination_port is None:
                    continue
                if ignore_localhost and (_is_loopback(source_ip) or _is_loopback(destination_ip)):
                    continue

                signature = (
                    pid,
                    "network",
                    source_ip,
                    _address_port(connection.laddr),
                    destination_ip,
                    destination_port,
                    connection.status,
                )
                if signature in _seen_putty_ports:
                    continue

                _seen_putty_ports.add(signature)
                protocol = "SSH" if destination_port == 22 else "TELNET" if destination_port == 23 else "TCP"
                rows.append(
                    {
                        "timestamp": captured_at,
                        "user_id": str(user_id),
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "protocol": protocol,
                        "action": _putty_port_action(protocol, destination_port, connection.status),
                        "bytes_sent": 0,
                        "bytes_received": 0,
                    }
                )
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied, OSError):
            continue

    return rows


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


def _collect_rows_scapy(
    ignore_localhost: bool = True,
    capture_seconds: int = COLLECTION_INTERVAL_SECONDS,
) -> list[dict[str, str | int]]:
    if sniff is None:
        print("scapy is not installed. Run `python -m pip install -r requirements.txt`.")
        return []

    try:
        packets = sniff(filter="ip", timeout=capture_seconds, store=True)
    except PermissionError as error:
        print(
            "Permission denied while capturing packets. "
            "Run PowerShell as Administrator and make sure Npcap is installed. "
            f"Details: {error}"
        )
        return []
    except OSError as error:
        print(
            "Unable to capture packets with Scapy. On Windows, install Npcap "
            f"and run as Administrator. Details: {error}"
        )
        return []
    except Exception as error:
        print(f"Unable to capture packets safely with Scapy: {error}")
        return []

    return _build_packet_rows(packets, ignore_localhost=ignore_localhost)


def collect_rows_once(
    ignore_localhost: bool = True,
    backend: str = "psutil",
    capture_seconds: int = COLLECTION_INTERVAL_SECONDS,
    client_id: str | None = None,
) -> list[dict[str, str | int]]:
    if backend == "scapy":
        rows = _collect_rows_scapy(
            ignore_localhost=ignore_localhost,
            capture_seconds=capture_seconds,
        )
    elif backend == "putty":
        rows = _collect_rows_putty(ignore_localhost=ignore_localhost)
    else:
        rows = _collect_rows_psutil(ignore_localhost=ignore_localhost)

    return _tag_rows_with_client_id(rows, client_id)


def collect_once(
    csv_path: Path = DEFAULT_DATA_PATH,
    ignore_localhost: bool = True,
    backend: str = "psutil",
    capture_seconds: int = COLLECTION_INTERVAL_SECONDS,
    server_url: str | None = None,
    client_id: str | None = None,
) -> int:
    ensure_events_file(csv_path)
    rows = collect_rows_once(
        ignore_localhost=ignore_localhost,
        backend=backend,
        capture_seconds=capture_seconds,
        client_id=client_id,
    )
    accepted_count = send_rows_to_server(server_url, rows) if server_url else 0
    local_count = _append_rows(csv_path, rows)
    return max(local_count, accepted_count)


def collect_and_append_events(
    csv_path: Path = DEFAULT_DATA_PATH,
    interval_seconds: int = COLLECTION_INTERVAL_SECONDS,
    ignore_localhost: bool = True,
    backend: str = "psutil",
    server_url: str | None = None,
    client_id: str | None = None,
    stop_event: threading.Event | None = None,
) -> None:
    ensure_events_file(csv_path)

    while stop_event is None or not stop_event.is_set():
        collect_once(
            csv_path=csv_path,
            ignore_localhost=ignore_localhost,
            backend=backend,
            capture_seconds=interval_seconds,
            server_url=server_url,
            client_id=client_id,
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
