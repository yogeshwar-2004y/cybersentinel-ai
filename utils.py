"""CSV validation, deterministic identifiers, and redaction boundaries."""

from __future__ import annotations
from hashlib import sha256
from io import BytesIO, StringIO
import csv
from typing import Any
import json
import logging
import re
import numpy as np
import pandas as pd
from config import Config, FEATURES

log = logging.getLogger(__name__)


def setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")


def validate_logs(df: pd.DataFrame, max_rows: int = 50000) -> pd.DataFrame:
    """Reject ambiguous/unsafe inputs; never silently impute missing features."""
    if df.empty or len(df) > max_rows:
        raise ValueError(f"Provide 1 to {max_rows:,} rows.")
    if df.columns.duplicated().any():
        raise ValueError("Duplicate CSV column names are not permitted.")
    missing = sorted(set(FEATURES) - set(df.columns))
    if missing:
        raise ValueError("Missing feature columns: " + ", ".join(missing))
    result = df.copy()
    for col in FEATURES:
        try:
            result[col] = pd.to_numeric(result[col], errors="raise").astype(float)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{col} must contain numeric values.") from exc
    values = result[list(FEATURES)].to_numpy()
    if not np.isfinite(values).all() or (values < 0).any() or (values > 1e15).any():
        raise ValueError("Features must be finite, non-negative, and at most 1e15.")
    if "timestamp" not in result:
        result["timestamp"] = pd.Timestamp.now(tz="UTC").isoformat()
    ts = pd.to_datetime(result["timestamp"], utc=True, errors="coerce")
    if ts.isna().any():
        raise ValueError("timestamp contains invalid dates.")
    result["timestamp"] = ts.map(lambda x: x.isoformat())
    for col, default in [
        ("source_ip", "unknown"),
        ("destination_ip", "unknown"),
        ("user", "unknown"),
        ("host", "unknown"),
        ("event_type", "Unspecified"),
        ("message", ""),
        ("asset_criticality", "medium"),
    ]:
        if col not in result:
            result[col] = default
        result[col] = result[col].fillna(default).astype(str).str.slice(0, 2000)
    # IDs include all evidence except demo labels and outputs, to avoid collisions across uploads.
    identity_cols = [
        c
        for c in result
        if c
        not in {
            "event_id",
            "ground_truth",
            "attack_label",
            "prediction",
            "anomaly_score",
            "confidence",
            "decision_function",
            "reference_percentile",
            "model_id",
            "threat_name",
            "severity",
            "risk_score",
        }
    ]
    result["event_id"] = [stable_id({c: row[c] for c in identity_cols}, "EVT") for _, row in result.iterrows()]
    return result.reset_index(drop=True)


def read_csv(data: bytes, config: Config) -> pd.DataFrame:
    if len(data) > config.max_upload_bytes:
        raise ValueError("CSV exceeds the 20 MiB limit.")
    try:
        header = next(csv.reader(StringIO(data.decode("utf-8-sig"))), [])
        if len(header) != len(set(header)):
            raise ValueError("Duplicate CSV column names are not permitted.")
        frame = pd.read_csv(BytesIO(data), nrows=config.max_rows + 1)
    except (pd.errors.ParserError, UnicodeDecodeError) as exc:
        raise ValueError("Unable to read UTF-8 CSV.") from exc
    return validate_logs(frame, config.max_rows)


def stable_id(value: Any, prefix: str = "INC") -> str:
    payload = json.dumps(value, sort_keys=True, default=str, allow_nan=False).encode()
    return f"{prefix}-{sha256(payload).hexdigest()[:16].upper()}"


def redact_text(text: str) -> str:
    text = re.sub(r"(?i)(password|secret|token|api[_-]?key|authorization)\s*[:=]\s*[^\s,;]+", r"\1=[REDACTED]", text)
    text = re.sub(r"(?i)bearer\s+[A-Za-z0-9._-]+", "Bearer [REDACTED]", text)
    text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "[IP]", text)
    text = re.sub(r"[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}", "[EMAIL]", text)
    return text


def cloud_event(event: dict[str, Any]) -> dict[str, Any]:
    """Allowlisted numerical features plus redacted telemetry; identifiers are omitted."""
    return {
        **{k: event[k] for k in FEATURES},
        **{k: event[k] for k in ("prediction", "anomaly_score", "confidence") if k in event},
        "message": redact_text(str(event.get("message", "")))[:1500],
        "asset_criticality": event.get("asset_criticality", "medium"),
    }
