from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ACTION_ALLOW = "allow"
ACTION_MONITOR = "monitor"
ACTION_BLOCK = "block"
ACTION_QUARANTINE = "quarantine"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = PROJECT_ROOT / "models" / "firewall_nn.keras"
PREPROCESSOR_PATH = PROJECT_ROOT / "models" / "firewall_preprocessor.pkl"
_NN_CACHE: tuple[Any, dict[str, Any]] | None = None


@dataclass(frozen=True)
class FirewallRecommendation:
    ai_action: str
    target_type: str
    target_value: str
    source_ip: str
    destination_ip: str
    protocol: str
    port: int | None
    duration_minutes: int
    confidence: float
    explanation: str


def _text(value: Any) -> str:
    return str(value or "")


def _score(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _infer_port(protocol: str, action: str) -> int | None:
    normalized = f"{protocol} {action}".lower()
    if "ssh" in normalized:
        return 22
    if "telnet" in normalized:
        return 23
    if "https" in normalized:
        return 443
    if "dns" in normalized:
        return 53
    return None


def _has_reason(reasons: str, phrase: str) -> bool:
    return phrase in reasons.lower()


def _load_nn_assets() -> tuple[Any, dict[str, Any]] | None:
    global _NN_CACHE
    if _NN_CACHE is not None:
        return _NN_CACHE
    if not MODEL_PATH.exists() or not PREPROCESSOR_PATH.exists():
        return None

    try:
        import tensorflow as tf

        model = tf.keras.models.load_model(MODEL_PATH)
        with PREPROCESSOR_PATH.open("rb") as file:
            metadata = pickle.load(file)
    except Exception:
        return None

    _NN_CACHE = (model, metadata)
    return _NN_CACHE


def _nn_action(alert: dict[str, Any]) -> tuple[str, float] | None:
    assets = _load_nn_assets()
    if assets is None:
        return None

    try:
        import pandas as pd

        model, metadata = assets
        reasons = _text(alert.get("reasons"))
        timestamp = pd.to_datetime(_text(alert.get("timestamp")), errors="coerce")
        hour = int(timestamp.hour) if not pd.isna(timestamp) else 0
        row = pd.DataFrame(
            [
                {
                    "user_id": _text(alert.get("user_id")),
                    "source_ip": _text(alert.get("source_ip")),
                    "destination_ip": _text(alert.get("destination_ip")),
                    "protocol": _text(alert.get("protocol")),
                    "action": _text(alert.get("action")),
                    "severity": _text(alert.get("severity")),
                    "hour": hour,
                    "bytes_sent": _score(alert.get("bytes_sent")),
                    "bytes_received": _score(alert.get("bytes_received")),
                    "score": _score(alert.get("score")),
                    "has_unusual_hour": int(_has_reason(reasons, "unusual access hour")),
                    "has_new_source_ip": int(_has_reason(reasons, "new source ip")),
                    "has_new_destination_ip": int(_has_reason(reasons, "new destination ip")),
                    "has_bytes_spike": int(_has_reason(reasons, "bytes sent spike")),
                    "has_burst_activity": int(_has_reason(reasons, "burst activity")),
                }
            ]
        )
        feature_columns = metadata["categorical_features"] + metadata["numeric_features"]
        encoded = metadata["preprocessor"].transform(row[feature_columns])
        probabilities = model.predict(encoded, verbose=0)[0]
        action_index = int(probabilities.argmax())
        return str(metadata["classes"][action_index]), float(probabilities[action_index])
    except Exception:
        return None


def recommend_firewall_action(alert: dict[str, Any]) -> FirewallRecommendation:
    """Recommend a firewall response for one scored alert.

    This is a deterministic AI-advisor baseline. It mirrors the eventual neural
    network contract, so a trained MLP can replace the decision block without
    changing the backend or frontend.
    """
    severity = _text(alert.get("severity"))
    reasons = _text(alert.get("reasons"))
    protocol = _text(alert.get("protocol")).upper()
    action = _text(alert.get("action"))
    source_ip = _text(alert.get("source_ip"))
    destination_ip = _text(alert.get("destination_ip"))
    bytes_sent = _score(alert.get("bytes_sent"))
    anomaly_score = _score(alert.get("score"))
    port = _infer_port(protocol, action)
    predicted = _nn_action(alert)
    nn_action, nn_confidence = predicted if predicted else ("", 0.0)

    if (nn_action == ACTION_QUARANTINE and nn_confidence >= 0.7) or (severity == "Critical" and anomaly_score >= 4.0):
        if _has_reason(reasons, "burst activity") and _has_reason(reasons, "bytes sent spike"):
            return FirewallRecommendation(
                ai_action=ACTION_QUARANTINE,
                target_type="source_ip",
                target_value=source_ip,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                port=port,
                duration_minutes=60,
                confidence=max(0.94, nn_confidence),
                explanation=(
                    "Critical repeated activity with abnormal data transfer. "
                    "Temporarily quarantine the source host."
                ),
            )
        return FirewallRecommendation(
            ai_action=ACTION_BLOCK,
            target_type="destination_ip",
            target_value=destination_ip,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            duration_minutes=45,
            confidence=max(0.9, nn_confidence),
            explanation="Critical anomaly. Block the suspicious destination while the alert is reviewed.",
        )

    if nn_action == ACTION_BLOCK and nn_confidence >= 0.7 and severity in {"High", "Critical", "Medium"}:
        return FirewallRecommendation(
            ai_action=ACTION_BLOCK,
            target_type="destination_ip",
            target_value=destination_ip,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            duration_minutes=30,
            confidence=nn_confidence,
            explanation="Neural firewall model recommends blocking this destination.",
        )

    if severity == "High":
        if "SSH" in protocol or "TELNET" in protocol or port in {22, 23}:
            return FirewallRecommendation(
                ai_action=ACTION_BLOCK,
                target_type="service",
                target_value=f"{destination_ip}:{port or protocol}",
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                port=port,
                duration_minutes=30,
                confidence=0.84,
                explanation="High-risk remote access behavior. Block this service to the destination.",
            )
        if _has_reason(reasons, "bytes sent spike") or bytes_sent >= 16000:
            return FirewallRecommendation(
                ai_action=ACTION_BLOCK,
                target_type="destination_ip",
                target_value=destination_ip,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                port=port,
                duration_minutes=30,
                confidence=0.82,
                explanation="High upload anomaly suggests possible data exfiltration.",
            )

    if severity == "Medium":
        return FirewallRecommendation(
            ai_action=ACTION_MONITOR,
            target_type="user_id",
            target_value=_text(alert.get("user_id")),
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            port=port,
            duration_minutes=15,
            confidence=0.66,
            explanation="Suspicious behavior is present, but monitoring is safer than blocking.",
        )

    return FirewallRecommendation(
        ai_action=ACTION_ALLOW,
        target_type="none",
        target_value="",
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        port=port,
        duration_minutes=0,
        confidence=0.4,
        explanation="No firewall action is required for this event.",
    )
