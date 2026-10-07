"""Reject invalid telemetry; verify baseline separation and anomaly ranking."""

import numpy as np
import pytest
from ml.detector import AnomalyDetector
from utils import validate_logs, read_csv


def test_clear_attacks_score_above_normal(scored):
    normal = scored.loc[scored.ground_truth == "normal", "anomaly_score"]
    malicious = scored.loc[scored.ground_truth == "anomaly", "anomaly_score"]
    assert malicious.median() > normal.median()
    assert ((scored.ground_truth == "anomaly") & (scored.prediction == -1)).sum() > 90
    assert scored.confidence.between(0, 1).all()
    assert set(scored.prediction) == {-1, 1}


def test_model_does_not_refit_on_upload(detector, scored):
    model_id = detector.reference_id
    scored_again = detector.score(scored.head(4))
    assert detector.reference_id == model_id
    np.testing.assert_allclose(scored_again.anomaly_score, scored.head(4).anomaly_score)
    assert scored_again.event_id.tolist() == scored.head(4).event_id.tolist()


def test_labels_are_not_training_features(scored):
    frame = scored.head(64).copy()
    original = AnomalyDetector().fit(frame)
    frame["ground_truth"] = "modified"
    frame["event_type"] = "Ransomware"
    modified = AnomalyDetector().fit(frame)
    assert original.reference_id == modified.reference_id


@pytest.mark.parametrize("value", [-1, float("inf"), float("nan"), "nonnumeric", 1e16])
def test_invalid_numeric_rejected(scored, value):
    data = scored.head(2).copy()
    data["bytes_sent"] = value
    with pytest.raises(ValueError):
        validate_logs(data)


def test_missing_feature_rejected(scored):
    with pytest.raises(ValueError, match="Missing"):
        validate_logs(scored.head().drop(columns=["unique_ports"]))


def test_timestamp_rejected(scored):
    data = scored.head(1).copy()
    data["timestamp"] = "not-a-time"
    with pytest.raises(ValueError, match="timestamp"):
        validate_logs(data)


def test_empty_and_excess_rows(scored):
    with pytest.raises(ValueError):
        validate_logs(scored.head(0))
    with pytest.raises(ValueError):
        validate_logs(scored.head(10), max_rows=5)


def test_csv_size_guard(config):
    with pytest.raises(ValueError, match="20 MiB"):
        read_csv(b"x" * (config.max_upload_bytes + 1), config)


def test_minimum_baseline(scored):
    with pytest.raises(ValueError, match="32"):
        AnomalyDetector().fit(scored.head(5))


def test_scoring_unfitted_rejected(scored):
    with pytest.raises(RuntimeError):
        AnomalyDetector().score(scored.head())


def test_duplicate_csv_columns_rejected(config):
    with pytest.raises(ValueError, match="Duplicate"):
        read_csv(b"bytes_sent,bytes_sent\n1,2\n", config)
