from __future__ import annotations

import csv
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any


RECOMMENDATION_FIELDS = [
    "id",
    "event_key",
    "timestamp",
    "user_id",
    "source_ip",
    "destination_ip",
    "protocol",
    "port",
    "severity",
    "score",
    "reasons",
    "ai_action",
    "target_type",
    "target_value",
    "duration_minutes",
    "confidence",
    "explanation",
    "status",
]

RULE_FIELDS = [
    "id",
    "recommendation_id",
    "created_at",
    "source_ip",
    "destination_ip",
    "protocol",
    "port",
    "action",
    "target_type",
    "target_value",
    "duration_minutes",
    "reason",
    "mode",
    "status",
]


def _read_csv(path: Path, fieldnames: list[str]) -> list[dict[str, str]]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return [{field: str(row.get(field, "")) for field in fieldnames} for row in reader]


def _write_csv(path: Path, fieldnames: list[str], rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({field: row.get(field, "") for field in fieldnames})


def list_recommendations(path: Path) -> list[dict[str, str]]:
    return _read_csv(path, RECOMMENDATION_FIELDS)


def list_rules(path: Path) -> list[dict[str, str]]:
    return _read_csv(path, RULE_FIELDS)


def make_event_key(alert: dict[str, Any]) -> str:
    return "|".join(
        str(alert.get(field, ""))
        for field in ("timestamp", "user_id", "source_ip", "destination_ip", "protocol", "score")
    )


def upsert_recommendations(path: Path, recommendations: list[dict[str, Any]]) -> list[dict[str, str]]:
    existing = list_recommendations(path)
    known_keys = {row["event_key"] for row in existing}
    rows: list[dict[str, Any]] = [*existing]

    for recommendation in recommendations:
        if recommendation["event_key"] in known_keys:
            continue
        row = {field: recommendation.get(field, "") for field in RECOMMENDATION_FIELDS}
        row["id"] = row.get("id") or uuid.uuid4().hex[:12]
        row["status"] = row.get("status") or "pending"
        rows.append(row)
        known_keys.add(str(row["event_key"]))

    _write_csv(path, RECOMMENDATION_FIELDS, rows)
    return list_recommendations(path)


def update_recommendation_status(path: Path, recommendation_id: str, status: str) -> dict[str, str] | None:
    rows = list_recommendations(path)
    updated: dict[str, str] | None = None
    for row in rows:
        if row["id"] == recommendation_id:
            row["status"] = status
            updated = row
            break
    _write_csv(path, RECOMMENDATION_FIELDS, rows)
    return updated


def apply_simulated_rule(rules_path: Path, recommendation: dict[str, str]) -> dict[str, str]:
    rules = list_rules(rules_path)
    rule = {
        "id": uuid.uuid4().hex[:12],
        "recommendation_id": recommendation["id"],
        "created_at": datetime.now().replace(microsecond=0).isoformat(),
        "source_ip": recommendation["source_ip"],
        "destination_ip": recommendation["destination_ip"],
        "protocol": recommendation["protocol"],
        "port": recommendation["port"],
        "action": recommendation["ai_action"],
        "target_type": recommendation["target_type"],
        "target_value": recommendation["target_value"],
        "duration_minutes": recommendation["duration_minutes"],
        "reason": recommendation["explanation"],
        "mode": "simulation",
        "status": "active",
    }
    rules.append(rule)
    _write_csv(rules_path, RULE_FIELDS, rules)
    return rule


def approve_recommendation(recommendations_path: Path, rules_path: Path, recommendation_id: str) -> dict[str, str] | None:
    recommendation = update_recommendation_status(recommendations_path, recommendation_id, "approved")
    if recommendation is None:
        return None
    if recommendation["ai_action"] in {"block", "quarantine"}:
        return apply_simulated_rule(rules_path, recommendation)
    return recommendation


def reject_recommendation(recommendations_path: Path, recommendation_id: str) -> dict[str, str] | None:
    return update_recommendation_status(recommendations_path, recommendation_id, "rejected")


def deactivate_rule(rules_path: Path, rule_id: str) -> dict[str, str] | None:
    rows = list_rules(rules_path)
    updated: dict[str, str] | None = None
    for row in rows:
        if row["id"] == rule_id:
            row["status"] = "inactive"
            updated = row
            break
    _write_csv(rules_path, RULE_FIELDS, rows)
    return updated
