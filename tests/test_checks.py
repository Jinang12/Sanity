from sanity.checks import (
    check_dangerous_commands,
    check_deletion_ratio,
    check_secrets,
    run_all_checks,
)
from sanity.config import SanityConfig
from sanity.models import DiffResult, FileDiff


def _make_diff(diff_text: str, path: str = "test.py",
               added: int = 0, deleted: int = 0,
               is_new: bool = False, is_deleted: bool = False) -> DiffResult:
    return DiffResult(
        files=[FileDiff(
            path=path,
            added_lines=added,
            deleted_lines=deleted,
            is_new=is_new,
            is_deleted=is_deleted,
            diff_text=diff_text,
        )],
        total_added=added,
        total_deleted=deleted,
    )


def _make_multi_file_diff(file_diffs: list[tuple[str, str, int, int]]) -> DiffResult:
    files = []
    total_added = 0
    total_deleted = 0
    for path, diff_text, added, deleted in file_diffs:
        files.append(FileDiff(
            path=path,
            added_lines=added,
            deleted_lines=deleted,
            diff_text=diff_text,
        ))
        total_added += added
        total_deleted += deleted
    return DiffResult(files=files, total_added=total_added, total_deleted=total_deleted)


# ── Deletion ratio tests ──


def test_deletion_ratio_passes_normal_diff():
    diff = _make_diff("+added line\n-deleted line", added=5, deleted=3)
    result = check_deletion_ratio(diff)
    assert result.passed is True
    assert result.severity == "LOW"


def test_deletion_ratio_flags_high_ratio():
    diff = _make_diff("+one\n-many", added=2, deleted=20)
    result = check_deletion_ratio(diff)
    assert result.passed is False
    assert result.severity == "HIGH"
    assert "10.0x" in result.reason
    assert "exceeds" in result.reason


def test_deletion_ratio_pure_deletion():
    diff = _make_diff("-deleted\n-also deleted", added=0, deleted=15)
    result = check_deletion_ratio(diff)
    assert result.passed is False
    assert result.severity == "HIGH"
    assert "Pure deletion" in result.reason


def test_deletion_ratio_new_files_only():
    diff = _make_diff("+new code", added=50, deleted=0, is_new=True)
    result = check_deletion_ratio(diff)
    assert result.passed is True
    assert result.severity == "LOW"


def test_deletion_ratio_empty_diff():
    diff = DiffResult()
    result = check_deletion_ratio(diff)
    assert result.passed is True


def test_deletion_ratio_custom_threshold():
    diff = _make_diff("+one\n-many", added=5, deleted=11)
    result_strict = check_deletion_ratio(diff, threshold=2.0)
    assert result_strict.passed is False
    result_lax = check_deletion_ratio(diff, threshold=3.0)
    assert result_lax.passed is True


def test_deletion_ratio_exact_threshold():
    diff = _make_diff("text", added=10, deleted=30)
    result = check_deletion_ratio(diff, threshold=3.0)
    assert result.passed is True
    assert "3.0x" in result.reason


# ── Secret detection tests ──


def test_secrets_passes_clean_diff():
    diff = _make_diff(
        "+import os\n+x = 42\n+print('hello')",
        added=3,
    )
    result = check_secrets(diff)
    assert result.passed is True
    assert result.severity == "LOW"


def test_secrets_detects_aws_access_key():
    diff = _make_diff(
        "+AWS_KEY = AKIAIOSFODNN7EXAMPLE",
        path="config.py",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert result.severity == "HIGH"
    assert "AWS access key" in result.reason
    assert "config.py" in result.reason


def test_secrets_detects_generic_api_key():
    diff = _make_diff(
        "+api_key = sk_live_abc123def456ghi789jkl012mno345",
        path="settings.py",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert "API key" in result.reason.lower() or "secret" in result.reason.lower()


def test_secrets_detects_private_key():
    diff = _make_diff(
        "+-----BEGIN RSA PRIVATE KEY-----\n+MIIEpAIBAAKCAQEA0Z...",
        path="id_rsa",
        added=2,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert "Private key" in result.reason


def test_secrets_detects_generic_token():
    diff = _make_diff(
        "+access_token = ghp_abcdefghijklmnopqrstuvwx1234567890",
        path=".env",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert ".env" in result.reason


def test_secrets_detects_password():
    diff = _make_diff(
        "+password = SuperSecret123!@#Extra",
        path="config.yml",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert "Password" in result.reason


def test_secrets_detects_connection_string():
    diff = _make_diff(
        "+DATABASE_URL = postgres://admin:s3cret@db.example.com:5432/prod",
        path="docker-compose.yml",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False


def test_secrets_ignores_deleted_lines():
    diff = _make_diff(
        "-api_key = sk_live_abc123def456ghi789jkl012mno345\n+# key removed",
        path="settings.py",
        added=1,
        deleted=1,
    )
    result = check_secrets(diff)
    assert result.passed is True


def test_secrets_detects_aws_secret_key():
    diff = _make_diff(
        "+aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        path="credentials",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert "AWS secret key" in result.reason


# ── Dangerous command tests ──


def test_dangerous_commands_passes_clean_diff():
    diff = _make_diff(
        "+import os\n+os.path.join('a', 'b')\n+print('done')",
        added=3,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is True
    assert result.severity == "LOW"


def test_dangerous_commands_detects_rm_rf():
    diff = _make_diff(
        "+rm -rf /tmp/data",
        path="cleanup.sh",
        added=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is False
    assert "rm -rf" in result.reason


def test_dangerous_commands_detects_drop_table():
    diff = _make_diff(
        '+cursor.execute("DROP TABLE users")',
        path="migrate.py",
        added=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is False
    assert "DROP TABLE" in result.reason


def test_dangerous_commands_detects_delete_without_where():
    diff = _make_diff(
        '+cursor.execute("DELETE FROM orders;")',
        path="db.py",
        added=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is False
    assert "DELETE without WHERE" in result.reason


def test_dangerous_commands_allows_delete_with_where():
    diff = _make_diff(
        '+cursor.execute("DELETE FROM orders WHERE id = 5")',
        path="db.py",
        added=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is True


def test_dangerous_commands_detects_truncate():
    diff = _make_diff(
        '+cursor.execute("TRUNCATE TABLE logs")',
        path="cleanup.py",
        added=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is False
    assert "TRUNCATE" in result.reason


def test_dangerous_commands_detects_force_push():
    diff = _make_diff(
        "+git push origin main --force",
        path="deploy.sh",
        added=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is False
    assert "force push" in result.reason


def test_dangerous_commands_detects_os_remove():
    diff = _make_diff(
        "+os.remove('/etc/passwd')",
        path="hack.py",
        added=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is False
    assert "os.remove" in result.reason


def test_dangerous_commands_detects_shutil_rmtree():
    diff = _make_diff(
        "+shutil.rmtree('/important/data')",
        path="cleanup.py",
        added=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is False
    assert "shutil.rmtree" in result.reason


def test_dangerous_commands_ignores_deleted_lines():
    diff = _make_diff(
        "-os.remove('/tmp/old')\n+# removed dangerous call",
        path="safe.py",
        added=1,
        deleted=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is True


# ── run_all_checks tests ──


def test_run_all_checks_clean_diff():
    diff = _make_diff("+import os\n+x = 1", added=2, deleted=0)
    results = run_all_checks(diff)
    assert len(results) == 4
    assert all(r.passed for r in results)


def test_run_all_checks_multiple_failures():
    diff = _make_diff(
        "+api_key = sk_live_abc123def456ghi789jkl012mno345\n"
        "+os.remove('/etc/passwd')",
        path="bad.py",
        added=2,
        deleted=20,
    )
    results = run_all_checks(diff)
    assert len(results) == 4
    failed = [r for r in results if not r.passed]
    assert len(failed) == 3
    names = {r.check_name for r in failed}
    assert names == {"deletion_ratio", "secret_detection", "dangerous_commands"}


def test_run_all_checks_returns_correct_types():
    diff = _make_diff("+hello", added=1)
    results = run_all_checks(diff)
    for r in results:
        assert hasattr(r, "check_name")
        assert hasattr(r, "passed")
        assert hasattr(r, "severity")
        assert hasattr(r, "reason")
        assert r.severity in ("LOW", "MEDIUM", "HIGH")


# -- Exclusion and inline ignore tests --


def test_secrets_skips_excluded_test_files():
    """A secret in a test file should be ignored when config has default excludes."""
    diff = _make_diff(
        "+api_key = sk_live_abc123def456ghi789jkl012mno345",
        path="tests/test_auth.py",
        added=1,
    )
    cfg = SanityConfig()  # default excludes include tests/**
    result = check_secrets(diff, config=cfg)
    assert result.passed is True


def test_secrets_skips_readme():
    diff = _make_diff(
        "+api_key = sk_live_abc123def456ghi789jkl012mno345",
        path="README.md",
        added=1,
    )
    cfg = SanityConfig()
    result = check_secrets(diff, config=cfg)
    assert result.passed is True


def test_secrets_still_flags_source_files():
    """A real secret in a non-excluded source file must still be caught."""
    diff = _make_diff(
        "+api_key = sk_live_abc123def456ghi789jkl012mno345",
        path="src/config.py",
        added=1,
    )
    cfg = SanityConfig()
    result = check_secrets(diff, config=cfg)
    assert result.passed is False
    assert "src/config.py" in result.reason


def test_dangerous_commands_skips_excluded_docs():
    diff = _make_diff(
        "+rm -rf /tmp/data",
        path="docs/cleanup_guide.md",
        added=1,
    )
    cfg = SanityConfig()
    result = check_dangerous_commands(diff, config=cfg)
    assert result.passed is True


def test_dangerous_commands_still_flags_scripts():
    diff = _make_diff(
        "+rm -rf /tmp/data",
        path="scripts/deploy.sh",
        added=1,
    )
    cfg = SanityConfig()
    result = check_dangerous_commands(diff, config=cfg)
    assert result.passed is False


def test_inline_ignore_skips_line():
    """A line with # sanity: ignore should not trigger any check."""
    diff = _make_diff(
        "+api_key = sk_live_abc123def456ghi789jkl012mno345  # sanity: ignore",
        path="src/config.py",
        added=1,
    )
    cfg = SanityConfig()
    result = check_secrets(diff, config=cfg)
    assert result.passed is True


def test_inline_ignore_only_affects_marked_line():
    """Only the marked line is skipped; other lines are still checked."""
    diff = _make_diff(
        "+api_key = sk_live_abc123def456ghi789jkl012mno345  # sanity: ignore\n"
        "+secret = abcdefghijklmnopqrstuvwxyz123456",
        path="src/config.py",
        added=2,
    )
    cfg = SanityConfig()
    result = check_secrets(diff, config=cfg)
    assert result.passed is False
    assert "src/config.py" in result.reason


def test_inline_ignore_works_for_dangerous_commands():
    diff = _make_diff(
        "+os.remove('/tmp/cache')  # sanity: ignore",
        path="src/cleanup.py",
        added=1,
    )
    cfg = SanityConfig()
    result = check_dangerous_commands(diff, config=cfg)
    assert result.passed is True


def test_run_all_checks_with_disabled_check():
    diff = _make_diff(
        "+api_key = sk_live_abc123def456ghi789jkl012mno345",
        path="src/config.py",
        added=1,
    )
    cfg = SanityConfig(disabled_checks=["secret_detection"])
    results = run_all_checks(diff, config=cfg)
    names = [r.check_name for r in results]
    assert "secret_detection" not in names
    assert "deletion_ratio" in names
    assert "dangerous_commands" in names


def test_run_all_checks_with_config_excludes_test_files():
    """End-to-end: run_all_checks with default config skips test file secrets."""
    diff = _make_multi_file_diff([
        ("tests/test_auth.py", "+api_key = AKIAIOSFODNN7EXAMPLE", 1, 0),
        ("src/app.py", "+import os\n+x = 1", 2, 0),
    ])
    cfg = SanityConfig()
    results = run_all_checks(diff, config=cfg)
    secret_result = next(r for r in results if r.check_name == "secret_detection")
    assert secret_result.passed is True


# -- Gap fix and new feature tests --


def test_secrets_detects_stripe_key():
    diff = _make_diff(
        "+stripe_key = 'sk_live_51H8xK2eZvKYlo2C0h3Jk9mN4pQ7rS8tU9vW0xY1zA2bC3dE4fG5hI6jK7lM8nO9pQ0rS1tU2vW3xY4z'",
        path="payments.py",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert "Stripe API key" in result.reason


def test_dangerous_commands_detects_delete_without_semicolon():
    diff = _make_diff(
        '+cursor.execute("DELETE FROM orders")',
        path="db.py",
        added=1,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is False
    assert "DELETE without WHERE" in result.reason


def test_dangerous_commands_allows_multiline_delete_with_where():
    diff = _make_diff(
        '+cursor.execute("""\n'
        '+  DELETE FROM users\n'
        '+  WHERE id = 1\n'
        '+""")',
        path="db.py",
        added=4,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is True


def test_high_entropy_secrets_detects_generic_key():
    from sanity.checks import check_high_entropy_secrets
    # A fake key that is high entropy but doesn't match AWS/Stripe patterns
    diff = _make_diff(
        '+firebase_auth_hash = "AIzaSyB-abcd1234efgh5678ijkl9012mnop3456"',
        path="config.py",
        added=1,
    )
    result = check_high_entropy_secrets(diff)
    assert result.passed is False
    assert "High entropy secret (firebase_auth_hash)" in result.reason


def test_high_entropy_secrets_ignores_placeholders():
    from sanity.checks import check_high_entropy_secrets
    diff = _make_diff(
        '+api_key = "YOUR_API_KEY_HERE_ABCDEFG"',
        path="example.py",
        added=1,
    )
    result = check_high_entropy_secrets(diff)
    assert result.passed is True


def test_high_entropy_secrets_ignores_normal_sentences():
    from sanity.checks import check_high_entropy_secrets
    diff = _make_diff(
        '+secret_message = "This is just a normal sentence that is long enough but low entropy."',
        path="app.py",
        added=1,
    )
    result = check_high_entropy_secrets(diff)
    assert result.passed is True
