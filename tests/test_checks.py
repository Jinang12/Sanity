from sanity.checks import (
    check_dangerous_commands,
    check_deletion_ratio,
    check_high_entropy_secrets,
    check_high_entropy_secrets_generic,
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
        "+AWS_KEY = AKIA0123456789ABCDEF",
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
        "+api_key = 00000000000000000000000000000000",
        path="settings.py",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert "API key" in result.reason.lower() or "secret" in result.reason.lower()


def test_secrets_detects_private_key():
    diff = _make_diff(
        "+-----BEGIN RSA PRIVATE KEY-----\n+FAKE00000000000000...",
        path="id_rsa",
        added=2,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert "Private key" in result.reason


def test_secrets_detects_generic_token():
    diff = _make_diff(
        "+access_token = ghp_0000000000000000000000000000000000",
        path=".env",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert ".env" in result.reason


def test_secrets_detects_password():
    diff = _make_diff(
        "+password = FakePassword123!@#Extra",
        path="config.yml",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False
    assert "Password" in result.reason


def test_secrets_detects_connection_string():
    diff = _make_diff(
        "+DATABASE_URL = postgres://admin:FakePassword@db.example.com:5432/prod",
        path="docker-compose.yml",
        added=1,
    )
    result = check_secrets(diff)
    assert result.passed is False


def test_secrets_ignores_deleted_lines():
    diff = _make_diff(
        "-api_key = 00000000000000000000000000000000\n+# key removed",
        path="settings.py",
        added=1,
        deleted=1,
    )
    result = check_secrets(diff)
    assert result.passed is True


def test_secrets_detects_aws_secret_key():
    diff = _make_diff(
        "+aws_secret_access_key = 0000000000000000000000000000000000000000",
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
    assert len(results) == 6
    assert all(r.passed for r in results)


def test_run_all_checks_multiple_failures():
    diff = _make_diff(
        "+api_key = 00000000000000000000000000000000\n"
        "+os.remove('/etc/passwd')",
        path="bad.py",
        added=2,
        deleted=20,
    )
    results = run_all_checks(diff)
    assert len(results) == 6
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
        "+api_key = 00000000000000000000000000000000",
        path="tests/test_auth.py",
        added=1,
    )
    cfg = SanityConfig()  # default excludes include tests/**
    result = check_secrets(diff, config=cfg)
    assert result.passed is True


def test_secrets_skips_readme():
    diff = _make_diff(
        "+api_key = 00000000000000000000000000000000",
        path="README.md",
        added=1,
    )
    cfg = SanityConfig()
    result = check_secrets(diff, config=cfg)
    assert result.passed is True


def test_secrets_still_flags_source_files():
    """A real secret in a non-excluded source file must still be caught."""
    diff = _make_diff(
        "+api_key = 00000000000000000000000000000000",
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
        "+api_key = 00000000000000000000000000000000  # sanity: ignore",
        path="src/config.py",
        added=1,
    )
    cfg = SanityConfig()
    result = check_secrets(diff, config=cfg)
    assert result.passed is True


def test_inline_ignore_only_affects_marked_line():
    """Only the marked line is skipped; other lines are still checked."""
    diff = _make_diff(
        "+api_key = 00000000000000000000000000000000  # sanity: ignore\n"
        "+secret = 00000000000000000000000000000000",
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
        "+api_key = 00000000000000000000000000000000",
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
        ("tests/test_auth.py", "+api_key = AKIA0123456789ABCDEF", 1, 0),
        ("src/app.py", "+import os\n+x = 1", 2, 0),
    ])
    cfg = SanityConfig()
    results = run_all_checks(diff, config=cfg)
    secret_result = next(r for r in results if r.check_name == "secret_detection")
    assert secret_result.passed is True


# -- Gap fix and new feature tests --


def test_secrets_detects_stripe_key():
    diff = _make_diff(
        "+stripe_key = 'sk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKE'",
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
        '+firebase_auth_hash = "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0"',
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


# -- GAP 1: Generic Tier 2 entropy check (no keyword required) --


def test_generic_entropy_detects_no_keyword_variable():
    """GAP 1: mongob= with no suspicious keyword should be caught by Tier 2."""
    from sanity.checks import check_high_entropy_secrets_generic
    diff = _make_diff(
        '+mongob="sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ"',
        path="config.py",
        added=1,
    )
    result = check_high_entropy_secrets_generic(diff)
    assert result.passed is False
    assert result.severity == "MEDIUM"
    assert "mongob" in result.reason


def test_generic_entropy_skips_uuid():
    """GAP 1: UUID format should NOT be flagged by Tier 2."""
    from sanity.checks import check_high_entropy_secrets_generic
    diff = _make_diff(
        '+request_id = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"',
        path="app.py",
        added=1,
    )
    result = check_high_entropy_secrets_generic(diff)
    assert result.passed is True


def test_generic_entropy_skips_sha1_hash():
    """GAP 1: A 40-char hex string (git SHA) should NOT be flagged."""
    from sanity.checks import check_high_entropy_secrets_generic
    diff = _make_diff(
        '+commit_sha = "da39a3ee5e6b4b0d3255bfef95601890afd80709"',
        path="deploy.py",
        added=1,
    )
    result = check_high_entropy_secrets_generic(diff)
    assert result.passed is True


def test_generic_entropy_skips_non_secret_varnames():
    """GAP 1: Variable named 'checksum' should be excluded."""
    from sanity.checks import check_high_entropy_secrets_generic
    diff = _make_diff(
        '+file_checksum = "z9x8w7v6u5t4s3r2q1p0o9n8m7l6k5j4"',
        path="verify.py",
        added=1,
    )
    result = check_high_entropy_secrets_generic(diff)
    assert result.passed is True


def test_generic_entropy_wired_into_run_all_checks():
    """Confirm check_high_entropy_secrets_generic appears in run_all_checks output."""
    diff = _make_diff("+x = 1", added=1)
    results = run_all_checks(diff)
    names = [r.check_name for r in results]
    assert "high_entropy_secrets_generic" in names


# -- GAP 2: Type-annotated assignments --


def test_keyword_entropy_type_annotated_assignment():
    """GAP 2: secret_key: str = '...' should be caught by keyword check."""
    from sanity.checks import check_high_entropy_secrets
    diff = _make_diff(
        '+secret_key: str = "sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ"',
        path="config.py",
        added=1,
    )
    result = check_high_entropy_secrets(diff)
    assert result.passed is False
    assert "secret_key" in result.reason


def test_generic_entropy_type_annotated_assignment():
    """GAP 2: Type annotations also work in generic Tier 2."""
    from sanity.checks import check_high_entropy_secrets_generic
    diff = _make_diff(
        '+mongob: str = "sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ"',
        path="config.py",
        added=1,
    )
    result = check_high_entropy_secrets_generic(diff)
    assert result.passed is False
    assert result.severity == "MEDIUM"


# -- GAP 3: Unquoted assignments --


def test_keyword_entropy_unquoted_env_style():
    """GAP 3: Unquoted .env-style db_credential=value should be caught."""
    from sanity.checks import check_high_entropy_secrets
    diff = _make_diff(
        "+db_credential=sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ",
        path=".env",
        added=1,
    )
    result = check_high_entropy_secrets(diff)
    assert result.passed is False
    assert "db_credential" in result.reason


def test_keyword_entropy_unquoted_yaml_style():
    """GAP 3: Unquoted YAML-style auth_credential: value should be caught."""
    from sanity.checks import check_high_entropy_secrets
    diff = _make_diff(
        "+auth_credential: sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ",
        path="config.yml",
        added=1,
    )
    result = check_high_entropy_secrets(diff)
    assert result.passed is False
    assert "auth_credential" in result.reason


def test_generic_entropy_unquoted_env_style():
    """GAP 3: Unquoted generic variable should also be caught by Tier 2."""
    from sanity.checks import check_high_entropy_secrets_generic
    diff = _make_diff(
        "+MONGOB=sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ",
        path=".env",
        added=1,
    )
    result = check_high_entropy_secrets_generic(diff)
    assert result.passed is False
    assert result.severity == "MEDIUM"


# -- GAP 4: Placeholder-exclusion bug --


def test_placeholder_fix_real_secret_containing_token_substring():
    """GAP 4: A real secret value containing 'token' as a substring should NOT be skipped."""
    from sanity.checks import check_high_entropy_secrets
    diff = _make_diff(
        '+auth_credential = "Rq7token8Xm3pLs9WvNz2Jk5BfYd6Ht4"',
        path="config.py",
        added=1,
    )
    result = check_high_entropy_secrets(diff)
    assert result.passed is False
    assert "auth_credential" in result.reason


def test_placeholder_fix_real_secret_containing_key_substring():
    """GAP 4: A real secret value containing 'key' as a substring should NOT be skipped."""
    from sanity.checks import check_high_entropy_secrets
    diff = _make_diff(
        '+auth_credential = "Xp3keyW9mR7sLq2Nv8Jk5BfYd6Ht4Zc1"',
        path="settings.py",
        added=1,
    )
    result = check_high_entropy_secrets(diff)
    assert result.passed is False


def test_placeholder_still_skips_obvious_placeholders():
    """GAP 4: Obvious placeholders like YOUR_xxx_HERE should still be skipped."""
    from sanity.checks import check_high_entropy_secrets
    diff = _make_diff(
        '+api_key = "YOUR_API_KEY_HERE_ABCDEFG"',
        path="example.py",
        added=1,
    )
    result = check_high_entropy_secrets(diff)
    assert result.passed is True


# -- GAP 5: Dict-literal syntax --


def test_dict_literal_secret_detected():
    """GAP 5: Dict literal {"mongo_uri": "secret"} should be caught."""
    from sanity.checks import check_high_entropy_secrets_generic
    diff = _make_diff(
        '+config = {"mongo_conn": "sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ"}',
        path="app.py",
        added=1,
    )
    result = check_high_entropy_secrets_generic(diff)
    assert result.passed is False
    assert "mongo_conn" in result.reason


# -- Manual testing bugfixes and refinements --


def test_dedup_against_disabled_secret_detection():
    """Item 1: with secret_detection disabled, AWS key is still flagged HIGH by gitleaks_rules."""
    diff = _make_diff(
        '+k = "AKIAQ3XM7PL2NR5TV6WZ"',
        path="src/config.py",
        added=1,
    )
    cfg = SanityConfig(disabled_checks=["secret_detection"])
    results = run_all_checks(diff, config=cfg)
    gitleaks_res = next((r for r in results if r.check_name == "gitleaks_rules"), None)
    assert gitleaks_res is not None
    assert gitleaks_res.passed is False
    assert gitleaks_res.severity == "HIGH"
    assert "aws-access-token" in gitleaks_res.reason or "AKIA" in gitleaks_res.reason or "gitleaks" in gitleaks_res.check_name


def test_stacked_findings_prevented():
    """Item 2: a line with a provider-format key produces only gitleaks HIGH finding and no generic-tier warning."""
    diff = _make_diff(
        '+client_oauth = "gho_FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6FAKE12"',
        path="src/auth.py",
        added=1,
    )
    cfg = SanityConfig()
    results = run_all_checks(diff, config=cfg)
    # Check that gitleaks flagged it
    gitleaks_res = next((r for r in results if r.check_name == "gitleaks_rules"), None)
    assert gitleaks_res is not None
    assert gitleaks_res.passed is False
    assert gitleaks_res.severity == "HIGH"
    # Check that generic entropy checks did not also flag the same line
    generic_res = next((r for r in results if r.check_name == "high_entropy_secrets_generic"), None)
    assert generic_res is not None
    assert generic_res.passed is True
    keyword_res = next((r for r in results if r.check_name == "high_entropy_secrets"), None)
    assert keyword_res is not None
    assert keyword_res.passed is True


def test_unquoted_value_noise_not_flagged_in_python_files():
    """Item 3: Ordinary Python expressions are not flagged by unquoted entropy matching."""
    diff = _make_diff(
        "+m = _KEYWORD_UNQUOTED_PATTERN.match(line)\n"
        "+raw = _load_from_sanityrc(project_dir)\n"
        "+threshold = cfg.entropy_threshold",
        path="src/sanity/checks.py",
        added=3,
    )
    cfg = SanityConfig()
    keyword_res = check_high_entropy_secrets(diff, config=cfg)
    assert keyword_res.passed is True
    generic_res = check_high_entropy_secrets_generic(diff, config=cfg)
    assert generic_res.passed is True


def test_unquoted_value_in_env_and_yaml_still_flagged():
    """Item 3: REAL_SECRET_TEST in .env and api_key in .yaml are still caught."""
    env_diff = _make_diff(
        "+REAL_SECRET_TEST=sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ",
        path=".env",
        added=1,
    )
    res_env = run_all_checks(env_diff)
    assert any(not r.passed for r in res_env)

    yaml_diff = _make_diff(
        "+api_key: sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ",
        path="config.yaml",
        added=1,
    )
    res_yaml = run_all_checks(yaml_diff)
    assert any(not r.passed for r in res_yaml)


def test_dangerous_commands_truncate_comments_and_messages_not_flagged():
    """Item 4: Comments and messages containing 'truncate' are not flagged."""
    diff = _make_diff(
        "+# Truncate extremely long lines\n"
        "+msg = '[DIFF TRUNCATED FOR LENGTH]'",
        path="src/llm.py",
        added=2,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is True


def test_dangerous_commands_truncate_sql_flagged():
    """Item 4: Real SQL TRUNCATE TABLE is flagged."""
    diff = _make_diff(
        "+cursor.execute('TRUNCATE TABLE users;')\n"
        "+cursor.execute('truncate table logs;')",
        path="db.py",
        added=2,
    )
    result = check_dangerous_commands(diff)
    assert result.passed is False
    assert "TRUNCATE" in result.reason


def test_check_secrets_ignores_placeholders():
    """Item 7: Placeholder values in check_secrets generic assignment patterns are skipped."""
    diff = _make_diff(
        '+api_key = "dummy"\n'
        '+api_key = "YOUR_API_KEY_HERE"\n'
        '+password = "changeme"\n'
        '+token = "xxxxxxxxxxxxxxxxxxxx"',
        path="src/config.py",
        added=4,
    )
    result = check_secrets(diff)
    assert result.passed is True


def test_check_secrets_flags_real_secret_and_key_substring():
    """Item 7: Real secrets and secrets with substring 'key' are still flagged."""
    diff = _make_diff(
        '+api_key = "x7K9_mQ2-vL5_pW1z"\n'
        '+api_key = "a1b2c3d4key5f6g7h8i9"',
        path="src/config.py",
        added=2,
    )
    result = check_secrets(diff)
    assert result.passed is False


def test_normalize_for_console():
    """Item 8: Normalizes typographic quotes, dashes, and non-ASCII chars."""
    from sanity.display import normalize_for_console
    raw = "\u2018single\u2019 \u201cdouble\u201d \u2014 em \u2013 en \u2026 ellipsis \u2713 check"
    normalized = normalize_for_console(raw)
    assert normalized == "'single' \"double\" - em - en ... ellipsis ? check"


# -- Release hardening tests --


def test_severity_aware_suppression_env_secret_is_high():
    """Item 1: REAL_SECRET_TEST in .env is reported as HIGH severity (not suppressed by gitleaks generic-api-key MEDIUM)."""
    diff = _make_diff(
        "+REAL_SECRET_TEST=sKf8jQ2nRw7xL5mP3vB9dT6hY4cA1gZ",
        path=".env",
        added=1,
    )
    results = run_all_checks(diff)
    from sanity.scorer import calculate_risk
    risk = calculate_risk(results)
    assert risk == "HIGH"

    high_res = next(r for r in results if r.check_name == "high_entropy_secrets")
    assert high_res.passed is False
    assert high_res.severity == "HIGH"


def test_severity_aware_suppression_ghp_no_generic_warning():
    """Item 1: A ghp_ provider key (HIGH) produces no generic-tier warning."""
    diff = _make_diff(
        '+gh_pat = "ghp_FAKE1FAKE2FAKE3FAKE4FAKE5FAKE6FAKE12"',
        path="src/auth.py",
        added=1,
    )
    results = run_all_checks(diff)
    gitleaks_res = next(r for r in results if r.check_name == "gitleaks_rules")
    assert gitleaks_res.passed is False
    assert gitleaks_res.severity == "HIGH"

    generic_res = next(r for r in results if r.check_name == "high_entropy_secrets_generic")
    assert generic_res.passed is True


def test_severity_aware_suppression_two_files_both_reported():
    """Item 1: Two files with the same secret line are both reported."""
    diff = _make_multi_file_diff([
        ("src/service_a.py", '+api_key = "x7K9_mQ2-vL5_pW1z"', 1, 0),
        ("src/service_b.py", '+api_key = "x7K9_mQ2-vL5_pW1z"', 1, 0),
    ])
    results = run_all_checks(diff)
    secrets_res = next(r for r in results if r.check_name == "secret_detection")
    assert secrets_res.passed is False
    assert "src/service_a.py" in secrets_res.reason
    assert "src/service_b.py" in secrets_res.reason


def test_sanity_state_directory_excluded():
    """Item 2: .sanity/** is excluded by default; snapshot files are not flagged."""
    line = '+{"tag": "sanity-snapshot-1", "secret": "AKIA0123456789ABCDEF"}'
    diff = _make_diff(line, path=".sanity/snapshots.jsonl", added=1)
    results = run_all_checks(diff)
    assert all(r.passed for r in results)


def test_display_summary_line_distinguishes_warnings_from_failures(capsys):
    """Item 5: Summary line reports warning(s) separately from failed checks."""
    from sanity.display import print_check_results
    from sanity.models import CheckResult

    # Case 1: Only warnings (MEDIUM)
    results_warn = [
        CheckResult("check1", False, "MEDIUM", "A medium warning"),
        CheckResult("check2", True, "LOW", "All good"),
    ]
    print_check_results(results_warn)
    captured = capsys.readouterr().out
    assert "1 warning(s), 1 passed." in captured
    assert "failed" not in captured

    # Case 2: Only failures (HIGH)
    results_fail = [
        CheckResult("check1", False, "HIGH", "A high failure"),
        CheckResult("check2", True, "LOW", "All good"),
    ]
    print_check_results(results_fail)
    captured = capsys.readouterr().out
    assert "1 check(s) failed, 1 passed." in captured
    assert "warning(s)" not in captured

    # Case 3: Both failures and warnings
    results_both = [
        CheckResult("check1", False, "HIGH", "A high failure"),
        CheckResult("check2", False, "MEDIUM", "A medium warning"),
        CheckResult("check3", True, "LOW", "All good"),
    ]
    print_check_results(results_both)
    captured = capsys.readouterr().out
    assert "1 check(s) failed, 1 warning(s), 1 passed." in captured

    # Case 4: All passed
    results_all_good = [
        CheckResult("check1", True, "LOW", "All good"),
    ]
    print_check_results(results_all_good)
    captured = capsys.readouterr().out
    assert "All 1 checks passed." in captured
