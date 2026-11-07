import pytest
from sanity.checks import check_gitleaks_rules, run_all_checks
from sanity.config import SanityConfig
from sanity.gitleaks_rules import _parse_rules, get_skipped_ids, load_rules
from sanity.models import DiffResult, FileDiff


def _make_diff(
    diff_text: str,
    path: str = "src/app.py",
    added: int = 1,
    deleted: int = 0,
) -> DiffResult:
    return DiffResult(
        files=[
            FileDiff(
                path=path,
                added_lines=added,
                deleted_lines=deleted,
                diff_text=diff_text,
            )
        ],
        total_added=added,
        total_deleted=deleted,
    )


def test_rules_load_successfully():
    rules = load_rules()
    skipped = get_skipped_ids()
    assert len(rules) > 0
    # Verify loaded count and skipped ids are retrievable
    assert len(rules) >= 190
    assert isinstance(skipped, list)
    print(f"Loaded rules: {len(rules)}, Skipped rules: {len(skipped)}")
    print(f"Skipped IDs: {skipped}")


def test_gitleaks_detects_provider_format_key():
    # Matches github-oauth rule (gho_ followed by 36 alphanumeric characters)
    # Uses obvious fake repetitive placeholder text
    fake_token = "gho_FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6FAKE12"
    diff = _make_diff(f'+client_oauth = "{fake_token}"', path="src/auth.py")
    result = check_gitleaks_rules(diff)
    assert result.passed is False
    assert result.severity == "HIGH"
    assert "github-oauth" in result.reason
    assert "src/auth.py" in result.reason
    # Ensure secret value is NOT exposed in the reason
    assert fake_token not in result.reason


def test_gitleaks_skips_ignored_line():
    fake_token = "gho_FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6FAKE12"
    diff = _make_diff(f'+client_oauth = "{fake_token}"  # sanity: ignore', path="src/auth.py")
    result = check_gitleaks_rules(diff)
    assert result.passed is True
    assert result.severity == "LOW"


def test_gitleaks_skips_excluded_path_tests():
    fake_token = "gho_FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6FAKE12"
    diff = _make_diff(f'+client_oauth = "{fake_token}"', path="tests/test_auth.py")
    result = check_gitleaks_rules(diff)
    assert result.passed is True


def test_gitleaks_skips_excluded_path_readme():
    fake_token = "gho_FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6FAKE12"
    diff = _make_diff(f'+Example: "{fake_token}"', path="README.md")
    result = check_gitleaks_rules(diff)
    assert result.passed is True


def test_gitleaks_entropy_threshold_skips_low_entropy_match():
    # Matches regex gho_[0-9a-zA-Z]{36} but is all 'A's -> entropy < 3.0
    low_entropy_token = "gho_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    diff = _make_diff(f'+dummy_token = "{low_entropy_token}"', path="src/auth.py")
    result = check_gitleaks_rules(diff)
    assert result.passed is True


def test_bad_regex_rule_is_skipped_without_crashing():
    synthetic_toml_data = {
        "rules": [
            {
                "id": "synthetic-broken-rule",
                "description": "Rule with invalid regex",
                "regex": "[unclosed-bracket",
            },
            {
                "id": "synthetic-valid-rule",
                "description": "Rule with valid regex",
                "regex": "valid_pattern_[0-9]+",
            },
        ]
    }
    rules, skipped, _ = _parse_rules(synthetic_toml_data)
    assert "synthetic-broken-rule" in skipped
    assert len(rules) == 1
    assert rules[0].id == "synthetic-valid-rule"


def test_gitleaks_deduplicates_with_builtin_secrets():
    # AWS access key is already caught by check_secrets
    diff = _make_diff("+AWS_KEY = AKIA0123456789ABCDEF", path="src/config.py")
    result = check_gitleaks_rules(diff)
    # gitleaks_rules skips lines already flagged by check_secrets to avoid double-reporting
    assert result.passed is True


def test_gitleaks_disabled_in_config():
    fake_token = "gho_FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6FAKE12"
    diff = _make_diff(f'+client_oauth = "{fake_token}"', path="src/auth.py")
    cfg = SanityConfig(disabled_checks=["gitleaks_rules"])
    results = run_all_checks(diff, config=cfg)
    assert "gitleaks_rules" not in [r.check_name for r in results]


def test_gitleaks_global_allowlist_path():
    # gitleaks.toml is in global allowlist paths
    fake_token = "gho_FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6FAKE12"
    diff = _make_diff(f'+token = "{fake_token}"', path="gitleaks.toml")
    result = check_gitleaks_rules(diff)
    assert result.passed is True


def test_gitleaks_generic_api_key_returns_medium_severity():
    # 'creds' triggers generic-api-key and is not matched by built-in check_secrets
    diff = _make_diff('+creds = "sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ"', path="src/config.py")
    result = check_gitleaks_rules(diff)
    assert result.passed is False
    assert result.severity == "MEDIUM"
    assert "generic-api-key" in result.reason


def test_gitleaks_provider_format_returns_high_severity():
    fake_token = "gho_FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6FAKE12"
    diff = _make_diff(f'+client_oauth = "{fake_token}"', path="src/auth.py")
    result = check_gitleaks_rules(diff)
    assert result.passed is False
    assert result.severity == "HIGH"
    assert "github-oauth" in result.reason


def test_gitleaks_detects_sendgrid_token():
    fake_token = "SG." + ("FAKE1FAKE2FAKE3" * 5)[:66]
    diff = _make_diff(f'+sg_key = "{fake_token}"', path="src/email.py")
    result = check_gitleaks_rules(diff)
    assert result.passed is False
    assert result.severity == "HIGH"
    assert "sendgrid-api-token" in result.reason
    assert "src/email.py" in result.reason
    assert fake_token not in result.reason


def test_gitleaks_detects_linear_api_key():
    fake_token = "lin_api_" + ("FAKE1FAKE2FAKE3" * 3)[:40]
    diff = _make_diff(f'+linear = "{fake_token}"', path="src/tasks.py")
    result = check_gitleaks_rules(diff)
    assert result.passed is False
    assert result.severity == "HIGH"
    assert "linear-api-key" in result.reason
    assert "src/tasks.py" in result.reason
    assert fake_token not in result.reason
