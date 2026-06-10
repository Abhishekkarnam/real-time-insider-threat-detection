from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler

try:
    import tensorflow as tf
except ImportError as error:  # pragma: no cover - friendly CLI failure
    raise SystemExit("Install TensorFlow first: python -m pip install tensorflow") from error

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SRC_PATH = PROJECT_ROOT / "src"
if str(SRC_PATH) not in sys.path:
    sys.path.insert(0, str(SRC_PATH))

from insider_threat_detection.pipeline import analyze_events


CATEGORICAL_FEATURES = ["user_id", "source_ip", "destination_ip", "protocol", "action", "severity"]
NUMERIC_FEATURES = [
    "hour",
    "bytes_sent",
    "bytes_received",
    "score",
    "has_unusual_hour",
    "has_new_source_ip",
    "has_new_destination_ip",
    "has_bytes_spike",
    "has_burst_activity",
]
ACTION_CLASSES = ["allow", "monitor", "block", "quarantine"]


def _flag_reason(reasons: str, phrase: str) -> int:
    return int(phrase in reasons.lower())


def _label_action(row: pd.Series) -> str:
    severity = str(row["severity"])
    reasons = str(row["reasons"]).lower()

    if severity == "Critical" and "burst activity" in reasons and "bytes sent spike" in reasons:
        return "quarantine"
    if severity == "Critical":
        return "block"
    if severity == "High":
        return "block"
    if severity == "Medium":
        return "monitor"
    return "allow"


def build_training_frame(csv_path: Path) -> pd.DataFrame:
    scored_events, _ = analyze_events(csv_path)
    if not scored_events:
        raise ValueError(f"No scored events found in {csv_path}")

    frame = pd.DataFrame(scored_events)
    frame["timestamp"] = pd.to_datetime(frame["timestamp"])
    frame["hour"] = frame["timestamp"].dt.hour
    frame["has_unusual_hour"] = frame["reasons"].apply(lambda value: _flag_reason(value, "unusual access hour"))
    frame["has_new_source_ip"] = frame["reasons"].apply(lambda value: _flag_reason(value, "new source ip"))
    frame["has_new_destination_ip"] = frame["reasons"].apply(lambda value: _flag_reason(value, "new destination ip"))
    frame["has_bytes_spike"] = frame["reasons"].apply(lambda value: _flag_reason(value, "bytes sent spike"))
    frame["has_burst_activity"] = frame["reasons"].apply(lambda value: _flag_reason(value, "burst activity"))
    frame["firewall_action"] = frame.apply(_label_action, axis=1)
    return frame


def train(csv_path: Path, model_path: Path, preprocessor_path: Path) -> None:
    frame = build_training_frame(csv_path)
    features = frame[CATEGORICAL_FEATURES + NUMERIC_FEATURES]
    labels = frame["firewall_action"].map({label: index for index, label in enumerate(ACTION_CLASSES)})

    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )

    preprocessor = ColumnTransformer(
        transformers=[
            ("categorical", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
            ("numeric", StandardScaler(), NUMERIC_FEATURES),
        ]
    )
    x_train_encoded = preprocessor.fit_transform(x_train)
    x_test_encoded = preprocessor.transform(x_test)

    input_dim = x_train_encoded.shape[1]
    model = tf.keras.Sequential(
        [
            tf.keras.layers.Input(shape=(input_dim,)),
            tf.keras.layers.Dense(64, activation="relu"),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(32, activation="relu"),
            tf.keras.layers.Dropout(0.2),
            tf.keras.layers.Dense(len(ACTION_CLASSES), activation="softmax"),
        ]
    )
    model.compile(optimizer="adam", loss="sparse_categorical_crossentropy", metrics=["accuracy"])
    model.fit(x_train_encoded, y_train, validation_split=0.15, epochs=35, batch_size=32, verbose=1)

    predictions = model.predict(x_test_encoded).argmax(axis=1)
    print(classification_report(y_test, predictions, target_names=ACTION_CLASSES))

    model_path.parent.mkdir(parents=True, exist_ok=True)
    preprocessor_path.parent.mkdir(parents=True, exist_ok=True)
    model.save(model_path)
    with preprocessor_path.open("wb") as file:
        pickle.dump(
            {
                "preprocessor": preprocessor,
                "categorical_features": CATEGORICAL_FEATURES,
                "numeric_features": NUMERIC_FEATURES,
                "classes": ACTION_CLASSES,
            },
            file,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the MLP firewall recommendation model.")
    parser.add_argument("--csv-path", type=Path, default=Path("data") / "network_events.csv")
    parser.add_argument("--model-path", type=Path, default=Path("models") / "firewall_nn.keras")
    parser.add_argument("--preprocessor-path", type=Path, default=Path("models") / "firewall_preprocessor.pkl")
    args = parser.parse_args()

    train(args.csv_path, args.model_path, args.preprocessor_path)


if __name__ == "__main__":
    main()
