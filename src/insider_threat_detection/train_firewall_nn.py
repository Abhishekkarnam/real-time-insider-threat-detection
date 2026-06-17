from __future__ import annotations

import argparse
import pickle
import sys
from pathlib import Path

from typing import Any, cast

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
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


EMBEDDED_FEATURES = ["user_id", "source_ip", "destination_ip"]
SMALL_CATEGORICAL_FEATURES = ["protocol", "action", "severity"]
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


def _flag_reason(reasons: str, phrase: str) -> int:
    return int(phrase in reasons.lower())


def _one_hot_encoder() -> OneHotEncoder:
    try:
        return OneHotEncoder(handle_unknown="ignore", sparse_output=False)
    except TypeError:
        return OneHotEncoder(handle_unknown="ignore", sparse=False)


def _build_vocab(values: pd.Series) -> dict[str, int]:
    unique_values = sorted(str(value) for value in values.dropna().unique())
    return {"<UNK>": 0, **{value: index + 1 for index, value in enumerate(unique_values)}}


def _embedding_dim(vocab_size: int) -> int:
    return max(2, min(16, int(np.ceil(np.sqrt(vocab_size))) + 1))


def _feature_indices(frame: pd.DataFrame, vocabularies: dict[str, dict[str, int]]) -> dict[str, np.ndarray]:
    inputs: dict[str, np.ndarray] = {}
    for feature in EMBEDDED_FEATURES:
        vocab = vocabularies[feature]
        inputs[f"{feature}_input"] = (
            frame[feature].astype(str).map(lambda value: vocab.get(value, 0)).to_numpy(dtype=np.int32)
        )
    return inputs


def _normalized_indices(
    frame: pd.DataFrame,
    vocabularies: dict[str, dict[str, int]],
    max_index_values: dict[str, int],
) -> np.ndarray:
    columns = []
    for feature in EMBEDDED_FEATURES:
        vocab = vocabularies[feature]
        max_index = max(max_index_values[feature], 1)
        values = frame[feature].astype(str).map(lambda value: vocab.get(value, 0)).to_numpy(dtype=np.float32)
        columns.append((values / max_index).reshape(-1, 1))
    return np.concatenate(columns, axis=1).astype(np.float32)


def _to_dense(matrix: object) -> np.ndarray:
    if hasattr(matrix, "toarray"):
        matrix = matrix.toarray()
    return np.asarray(matrix, dtype=np.float32)


def _build_model(
    vocabularies: dict[str, dict[str, int]],
    dense_dim: int,
    target_dim: int,
) -> tf.keras.Model:
    model_inputs: list[tf.keras.layers.Input] = []
    encoded_parts: list[tf.Tensor] = []

    for feature in EMBEDDED_FEATURES:
        vocab_size = len(vocabularies[feature])
        embedding_size = _embedding_dim(vocab_size)
        feature_input = tf.keras.layers.Input(shape=(), dtype="int32", name=f"{feature}_input")
        embedding = tf.keras.layers.Embedding(
            input_dim=vocab_size,
            output_dim=embedding_size,
            name=f"{feature}_embedding",
        )(feature_input)
        model_inputs.append(feature_input)
        encoded_parts.append(tf.keras.layers.Flatten()(embedding))

    dense_input = tf.keras.layers.Input(shape=(dense_dim,), name="dense_features")
    model_inputs.append(dense_input)
    encoded_parts.append(dense_input)

    merged = tf.keras.layers.Concatenate(name="embedded_event_features")(encoded_parts)
    hidden = tf.keras.layers.Dense(96, activation="relu")(merged)
    hidden = tf.keras.layers.Dropout(0.2)(hidden)
    hidden = tf.keras.layers.Dense(48, activation="relu")(hidden)
    bottleneck = tf.keras.layers.Dense(16, activation="relu", name="behavior_bottleneck")(hidden)
    hidden = tf.keras.layers.Dense(48, activation="relu")(bottleneck)
    hidden = tf.keras.layers.Dense(96, activation="relu")(hidden)
    output = tf.keras.layers.Dense(target_dim, activation="linear", name="reconstructed_event")(hidden)

    model = tf.keras.Model(inputs=model_inputs, outputs=output, name="embedding_autoencoder")
    model.compile(optimizer="adam", loss="mse")
    return model


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
    return frame


def train(csv_path: Path, model_path: Path, preprocessor_path: Path) -> None:
    frame = build_training_frame(csv_path)
    normal_frame = frame[
        (frame["severity"].isin(["Normal", "Low"]))
        & (frame["score"].astype(float) < 2.5)
    ].copy()
    if normal_frame.empty:
        raise ValueError("No normal/low-risk events found. Autoencoder training needs clean baseline traffic.")

    feature_columns = EMBEDDED_FEATURES + SMALL_CATEGORICAL_FEATURES + NUMERIC_FEATURES
    x_train, x_test = train_test_split(
        normal_frame[feature_columns],
        test_size=0.2,
        random_state=42,
    )

    vocabularies = {feature: _build_vocab(x_train[feature]) for feature in EMBEDDED_FEATURES}
    max_index_values = {feature: max(vocabularies[feature].values()) for feature in EMBEDDED_FEATURES}
    dense_preprocessor = ColumnTransformer(
        transformers=[
            ("categorical", _one_hot_encoder(), SMALL_CATEGORICAL_FEATURES),
            ("numeric", StandardScaler(), NUMERIC_FEATURES),
        ]
    )

    x_train_dense = _to_dense(dense_preprocessor.fit_transform(x_train))
    x_test_dense = _to_dense(dense_preprocessor.transform(x_test))
    train_inputs = _feature_indices(x_train, vocabularies)
    test_inputs = _feature_indices(x_test, vocabularies)
    train_inputs["dense_features"] = x_train_dense
    test_inputs["dense_features"] = x_test_dense

    y_train = np.concatenate(
        [_normalized_indices(x_train, vocabularies, max_index_values), x_train_dense],
        axis=1,
    )
    y_test = np.concatenate(
        [_normalized_indices(x_test, vocabularies, max_index_values), x_test_dense],
        axis=1,
    )

    model = _build_model(vocabularies, dense_dim=x_train_dense.shape[1], target_dim=y_train.shape[1])
    model.fit(
        train_inputs,
        y_train,
        validation_data=(test_inputs, y_test),
        epochs=50,
        batch_size=32,
        verbose=1,
    )

    reconstructed = model.predict(train_inputs, verbose=0)
    reconstruction_errors = ((y_train - reconstructed) ** 2).mean(axis=1)
    threshold = float(pd.Series(reconstruction_errors).quantile(0.95))
    quarantine_threshold = float(threshold * 2.0)
    print(f"Trained embedding autoencoder on {len(y_train)} normal events")
    print(f"Dense feature dimensions: {x_train_dense.shape[1]}")
    print(f"Reconstruction target dimensions: {y_train.shape[1]}")
    print(f"95th percentile reconstruction threshold: {threshold:.6f}")

    model_path.parent.mkdir(parents=True, exist_ok=True)
    preprocessor_path.parent.mkdir(parents=True, exist_ok=True)
    model.save(model_path)
    with preprocessor_path.open("wb") as file:
        pickle.dump(
            {
                "dense_preprocessor": dense_preprocessor,
                "embedded_features": EMBEDDED_FEATURES,
                "small_categorical_features": SMALL_CATEGORICAL_FEATURES,
                "numeric_features": NUMERIC_FEATURES,
                "vocabularies": vocabularies,
                "max_index_values": max_index_values,
                "model_type": "embedding_autoencoder",
                "reconstruction_threshold": threshold,
                "quarantine_threshold": quarantine_threshold,
            },
            file,
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Train the autoencoder firewall anomaly model.")
    parser.add_argument("--csv-path", type=Path, default=Path("data") / "network_events.csv")
    parser.add_argument("--model-path", type=Path, default=Path("models") / "firewall_nn.keras")
    parser.add_argument("--preprocessor-path", type=Path, default=Path("models") / "firewall_preprocessor.pkl")
    args = parser.parse_args()

    train(args.csv_path, args.model_path, args.preprocessor_path)


if __name__ == "__main__":
    main()
