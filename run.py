"""Start Streamlit with `python run.py`; or produce a headless end-to-end demo."""

import argparse
from pathlib import Path
import subprocess
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="CyberSentinel AI launcher")
    parser.add_argument("--demo", action="store_true", help="Run headless local investigation and export all formats")
    parser.add_argument("--port", type=int, default=8501)
    parser.add_argument("--host", default="127.0.0.1", help="Bind address; use 0.0.0.0 behind an authenticated gateway")
    parser.add_argument("--output", type=Path, default=Path("state/demo_exports"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parent
    if args.demo:
        from dataclasses import replace
        import pandas as pd
        from config import Config
        from ml.detector import AnomalyDetector
        from workflow import SOCWorkflow
        from report.generator import ReportGenerator

        config = replace(Config(), provider="local")
        detector = AnomalyDetector(config.contamination).fit(pd.read_csv(root / "data/baseline_logs.csv"))
        scored = detector.score(pd.read_csv(config.dataset_path))
        found = scored[scored.prediction == -1].sort_values("anomaly_score", ascending=False)
        if found.empty:
            raise RuntimeError("Demo produced no anomalies.")
        workflow = SOCWorkflow(config)
        report = workflow.investigate(found.iloc[0].to_dict())
        args.output.mkdir(parents=True, exist_ok=True)
        base = args.output / report["incident_id"]
        base.with_suffix(".md").write_text(ReportGenerator.markdown(report), encoding="utf-8")
        base.with_suffix(".json").write_bytes(ReportGenerator.json_bytes(report))
        base.with_suffix(".pdf").write_bytes(ReportGenerator.pdf_bytes(report))
        print(f"Scored {len(scored)} rows; detected {len(found)} anomalies. Retrieval: {workflow.retriever.mode}")
        print(f"Incident {report['incident_id']} exported to {args.output.resolve()}")
    else:
        if not 1 <= args.port <= 65535:
            parser.error("Port must be 1-65535")
        raise SystemExit(
            subprocess.call(
                [
                    sys.executable,
                    "-m",
                    "streamlit",
                    "run",
                    str(root / "app.py"),
                    "--server.port",
                    str(args.port),
                    "--server.address",
                    args.host,
                ],
                cwd=root,
            )
        )


if __name__ == "__main__":
    main()
