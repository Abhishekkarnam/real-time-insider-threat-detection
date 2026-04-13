from __future__ import annotations

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path


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


def _build_user_context(user_count: int) -> list[dict[str, object]]:
    users = [f"user_{index + 1}" for index in range(user_count)]
    destinations = [f"10.0.0.{index}" for index in range(10, 25)]
    source_ranges = [f"192.168.1.{index}" for index in range(2, 15)]
    contexts: list[dict[str, object]] = []

    for user in users:
        contexts.append(
            {
                "user_id": user,
                "preferred_hour": random.randint(8, 17),
                "normal_destinations": random.sample(destinations, 4),
                "normal_source": random.choice(source_ranges),
            }
        )

    return contexts


def _read_existing_rows(csv_path: Path) -> list[dict[str, str]]:
    if not csv_path.exists():
        return []

    with csv_path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return list(reader)


def _write_rows(output_path: Path, rows: list[dict[str, str | int]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)


def _append_rows(output_path: Path, rows: list[dict[str, str | int]]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    file_exists = output_path.exists()
    with output_path.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=FIELDNAMES)
        if not file_exists:
            writer.writeheader()
        writer.writerows(rows)


def generate_sample_events_csv(
    output_path: Path,
    user_count: int = 5,
    events_per_user: int = 60,
    seed: int = 7,
) -> None:
    random.seed(seed)
    protocols = ["TCP", "UDP", "HTTPS", "DNS"]
    actions = ["login", "file_access", "email", "database_query"]
    contexts = _build_user_context(user_count)

    start_time = datetime.now().replace(minute=0, second=0, microsecond=0) - timedelta(days=3)
    rows: list[dict[str, str | int]] = []

    for context in contexts:
        user_id = str(context["user_id"])
        preferred_hour = int(context["preferred_hour"])
        normal_destinations = list(context["normal_destinations"])
        normal_source = str(context["normal_source"])

        for event_index in range(events_per_user):
            timestamp = start_time + timedelta(minutes=20 * event_index) + timedelta(
                hours=max(0, preferred_hour - 8)
            )
            timestamp = timestamp.replace(hour=min(23, max(0, preferred_hour + random.randint(-2, 2))))

            suspicious = event_index >= events_per_user - 4 and user_id == str(contexts[-1]["user_id"])
            row = {
                "timestamp": timestamp.isoformat(),
                "user_id": user_id,
                "source_ip": f"172.16.99.{random.randint(100, 220)}" if suspicious else normal_source,
                "destination_ip": random.choice([f"10.0.0.{index}" for index in range(10, 25)])
                if suspicious
                else random.choice(normal_destinations),
                "protocol": random.choice(protocols),
                "action": random.choice(actions),
                "bytes_sent": random.randint(15000, 30000) if suspicious else random.randint(400, 4000),
                "bytes_received": random.randint(8000, 20000) if suspicious else random.randint(300, 2500),
            }
            rows.append(row)

    rows.sort(key=lambda item: item["timestamp"])
    _write_rows(output_path, rows)


def append_live_events_csv(
    output_path: Path,
    user_count: int = 6,
    events_to_add: int = 8,
    seed: int | None = None,
) -> None:
    if seed is not None:
        random.seed(seed)

    protocols = ["TCP", "UDP", "HTTPS", "DNS"]
    actions = ["login", "file_access", "email", "database_query"]
    destinations = [f"10.0.0.{index}" for index in range(10, 25)]
    existing_rows = _read_existing_rows(output_path)
    contexts = _build_user_context(user_count)

    if existing_rows:
        last_timestamp = max(
            datetime.fromisoformat(str(row["timestamp"]))
            for row in existing_rows
        )
    else:
        last_timestamp = datetime.now().replace(second=0, microsecond=0) - timedelta(minutes=5)

    new_rows: list[dict[str, str | int]] = []
    risky_user_id = str(contexts[-1]["user_id"])

    for event_index in range(events_to_add):
        context = contexts[event_index % len(contexts)]
        user_id = str(context["user_id"])
        preferred_hour = int(context["preferred_hour"])
        normal_destinations = list(context["normal_destinations"])
        normal_source = str(context["normal_source"])

        timestamp = last_timestamp + timedelta(minutes=5 * (event_index + 1))
        if event_index % 3 == 0:
            timestamp = timestamp.replace(hour=min(23, max(0, preferred_hour + random.randint(-2, 2))))

        suspicious = user_id == risky_user_id and random.random() < 0.55
        row = {
            "timestamp": timestamp.isoformat(),
            "user_id": user_id,
            "source_ip": f"172.16.99.{random.randint(100, 220)}" if suspicious else normal_source,
            "destination_ip": random.choice(destinations) if suspicious else random.choice(normal_destinations),
            "protocol": random.choice(protocols),
            "action": random.choice(actions),
            "bytes_sent": random.randint(16000, 32000) if suspicious else random.randint(500, 4500),
            "bytes_received": random.randint(9000, 22000) if suspicious else random.randint(350, 2800),
        }
        new_rows.append(row)

    _append_rows(output_path, new_rows)
