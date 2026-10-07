"""CLI for fitting and evaluating the synthetic reference without test leakage."""

import argparse
from pathlib import Path
import pandas as pd
from sklearn.metrics import classification_report
from config import Config
from ml.detector import AnomalyDetector


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--evaluate", type=Path)
    args = parser.parse_args()
    config = Config()
    frame = pd.read_csv(args.reference or (config.dataset_path.parent / "baseline_logs.csv"))
    # Ground truth is used only to select demo baseline, never as an input feature.
    baseline = frame[frame["ground_truth"] == "normal"] if "ground_truth" in frame else frame
    train = baseline.iloc[: int(len(baseline) * 0.8)]
    detector = AnomalyDetector(config.contamination).fit(train)
    test = pd.read_csv(args.evaluate or config.dataset_path)
    scored = detector.score(test)
    detector.save_metadata(config.state_dir / "model_metadata.json")
    print(f"Trained {detector.reference_id}; evaluated {len(scored)} rows")
    if "ground_truth" in scored:
        print(
            classification_report(
                scored["ground_truth"] != "normal",
                scored["prediction"] == -1,
                target_names=["normal", "anomaly"],
                zero_division=0,
            )
        )
    else:
        print(scored[["event_id", "prediction", "anomaly_score"]].to_string(index=False))


if __name__ == "__main__":
    main()
