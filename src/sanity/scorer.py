import json
import time
from pathlib import Path

from sanity.models import CheckResult, DiffResult


def calculate_risk(results: list[CheckResult]) -> str:
    if any(not r.passed and r.severity == "HIGH" for r in results):
        return "HIGH"
    if any(not r.passed and r.severity == "MEDIUM" for r in results):
        return "MEDIUM"
    return "LOW"


def log_override(diff: DiffResult, overridden_checks: list[str]) -> None:
    log_dir = Path(".sanity")
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "override_log.jsonl"
    
    entry = {
        "timestamp": time.time(),
        "files_changed": [f.path for f in diff.files],
        "overridden_checks": overridden_checks,
    }
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
