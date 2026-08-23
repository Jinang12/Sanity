import json
from pathlib import Path
from unittest.mock import patch

from click.testing import CliRunner

from sanity.cli import main
from sanity.models import CheckResult, DiffResult, FileDiff
from sanity.scorer import calculate_risk, log_override


def test_calculate_risk():
    res_pass = CheckResult("c1", True, "LOW", "ok")
    res_warn = CheckResult("c2", False, "MEDIUM", "warn")
    res_fail = CheckResult("c3", False, "HIGH", "fail")

    assert calculate_risk([res_pass]) == "LOW"
    assert calculate_risk([res_pass, res_warn]) == "MEDIUM"
    assert calculate_risk([res_warn, res_fail]) == "HIGH"
    assert calculate_risk([res_pass, res_warn, res_fail]) == "HIGH"
    assert calculate_risk([]) == "LOW"


def test_log_override(tmp_path):
    diff = DiffResult([FileDiff("test.py", True, False, False, None, 1, 0, "")], 1, 0)
    
    with patch("sanity.scorer.Path") as mock_path:
        mock_path.return_value = tmp_path
        log_override(diff, ["dangerous_commands"])
        
        log_file = tmp_path / "override_log.jsonl"
        assert log_file.exists()
        content = log_file.read_text(encoding="utf-8").strip()
        data = json.loads(content)
        assert data["files_changed"] == ["test.py"]
        assert data["overridden_checks"] == ["dangerous_commands"]
        assert "timestamp" in data


@patch("sanity.diff.get_staged_diff")
@patch("sanity.checks.run_all_checks")
def test_cli_high_risk_blocks_without_force(mock_run_checks, mock_get_diff):
    diff = DiffResult([FileDiff("a.py", False, False, False, None, 1, 0, "+a")], 1, 0)
    mock_get_diff.return_value = diff
    
    mock_run_checks.return_value = [CheckResult("dangerous_commands", False, "HIGH", "bad")]

    runner = CliRunner()
    result = runner.invoke(main, ["check"])
    
    assert result.exit_code == 1
    assert "Overall risk: HIGH -- commit blocked. Use --force to override" in result.output


@patch("sanity.diff.get_staged_diff")
@patch("sanity.checks.run_all_checks")
@patch("sanity.scorer.log_override")
def test_cli_high_risk_allowed_with_force(mock_log, mock_run_checks, mock_get_diff):
    diff = DiffResult([FileDiff("a.py", False, False, False, None, 1, 0, "+a")], 1, 0)
    mock_get_diff.return_value = diff
    
    mock_run_checks.return_value = [CheckResult("secret_detection", False, "HIGH", "bad secret")]

    runner = CliRunner()
    result = runner.invoke(main, ["check", "--force"])
    
    assert result.exit_code == 0
    assert "Overall risk: HIGH -- commit allowed (--force used)" in result.output
    assert "WARNING: You have forcibly overridden the following HIGH risk failures: secret_detection" in result.output
    mock_log.assert_called_once_with(diff, ["secret_detection"])
