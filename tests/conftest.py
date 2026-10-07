"""Independent fixtures keep tests offline and isolate persistent state."""

from dataclasses import replace
from pathlib import Path
import sys
import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from config import Config
from ml.detector import AnomalyDetector
from workflow import SOCWorkflow


@pytest.fixture
def config(tmp_path):
    return replace(
        Config(),
        provider="local",
        embedding_backend="hashing",
        state_dir=tmp_path,
        allow_cloud_logs=False,
        allow_fallback=True,
    )


@pytest.fixture(scope="session")
def detector():
    return AnomalyDetector().fit(pd.read_csv(ROOT / "data/baseline_logs.csv"))


@pytest.fixture(scope="session")
def scored(detector):
    return detector.score(pd.read_csv(ROOT / "data/security_logs.csv"))


@pytest.fixture
def workflow(config):
    return SOCWorkflow(config)


@pytest.fixture
def anomaly(scored):
    return (
        scored.loc[(scored.prediction == -1) & (scored.message.str.contains("authentication failures"))]
        .iloc[0]
        .to_dict()
    )


@pytest.fixture
def report(workflow, anomaly):
    return workflow.investigate(anomaly)
