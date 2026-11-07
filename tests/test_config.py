import os
from pathlib import Path

from sanity.config import (
    DEFAULT_EXCLUDE_PATTERNS,
    IGNORE_MARKER,
    SanityConfig,
    load_config,
)


# -- SanityConfig.is_excluded tests --


def test_excludes_test_files():
    cfg = SanityConfig()
    assert cfg.is_excluded("test_utils.py") is True
    assert cfg.is_excluded("utils_test.py") is True


def test_excludes_tests_directory():
    cfg = SanityConfig()
    assert cfg.is_excluded("tests/test_foo.py") is True
    assert cfg.is_excluded("tests/unit/test_bar.py") is True


def test_excludes_markdown_files():
    cfg = SanityConfig()
    assert cfg.is_excluded("README.md") is True
    assert cfg.is_excluded("README.rst") is True  # README* matches this
    assert cfg.is_excluded("CHANGELOG.md") is True
    assert cfg.is_excluded("CHANGELOG") is True
    assert cfg.is_excluded("docs/guide.md") is True


def test_excludes_docs_directory():
    cfg = SanityConfig()
    assert cfg.is_excluded("docs/api.md") is True
    assert cfg.is_excluded("docs/tutorial/step1.py") is True


def test_excludes_examples_directory():
    cfg = SanityConfig()
    assert cfg.is_excluded("examples/demo.py") is True
    assert cfg.is_excluded("examples/advanced/run.sh") is True


def test_does_not_exclude_source_files():
    cfg = SanityConfig()
    assert cfg.is_excluded("src/app.py") is False
    assert cfg.is_excluded("config.py") is False
    assert cfg.is_excluded("main.py") is False
    assert cfg.is_excluded(".env") is False
    assert cfg.is_excluded("deploy.sh") is False


def test_custom_exclude_patterns():
    cfg = SanityConfig(exclude_patterns=["vendor/**", "*.generated.py"])
    assert cfg.is_excluded("vendor/lib/util.py") is True
    assert cfg.is_excluded("output.generated.py") is True
    assert cfg.is_excluded("src/app.py") is False
    # Default patterns NOT present when overriding completely
    assert cfg.is_excluded("test_foo.py") is False


def test_empty_exclude_patterns():
    cfg = SanityConfig(exclude_patterns=[])
    assert cfg.is_excluded("test_foo.py") is False
    assert cfg.is_excluded("README.md") is False


def test_backslash_normalization():
    cfg = SanityConfig()
    assert cfg.is_excluded("tests\\test_foo.py") is True
    assert cfg.is_excluded("docs\\guide.md") is True


# -- load_config tests --


def test_load_config_defaults(tmp_path):
    cfg = load_config(str(tmp_path))
    assert cfg.exclude_patterns == list(DEFAULT_EXCLUDE_PATTERNS)
    assert cfg.disabled_checks == []
    assert cfg.deletion_ratio_threshold == 3.0


def test_load_config_from_pyproject(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.sanity]\n'
        'exclude = ["vendor/**"]\n'
        'deletion_ratio_threshold = 5.0\n'
        'disabled_checks = ["secret_detection"]\n'
    )
    cfg = load_config(str(tmp_path))
    assert "vendor/**" in cfg.exclude_patterns
    # Defaults are still present
    assert "test_*.py" in cfg.exclude_patterns
    assert cfg.deletion_ratio_threshold == 5.0
    assert "secret_detection" in cfg.disabled_checks


def test_load_config_from_sanityrc(tmp_path):
    rc = tmp_path / ".sanityrc"
    rc.write_bytes(b'exclude = ["custom/**"]\n')
    cfg = load_config(str(tmp_path))
    assert "custom/**" in cfg.exclude_patterns
    assert "test_*.py" in cfg.exclude_patterns


def test_sanityrc_takes_priority_over_pyproject(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text('[tool.sanity]\ndeletion_ratio_threshold = 10.0\n')
    rc = tmp_path / ".sanityrc"
    rc.write_bytes(b'deletion_ratio_threshold = 2.0\n')
    cfg = load_config(str(tmp_path))
    assert cfg.deletion_ratio_threshold == 2.0


def test_load_config_exclude_override(tmp_path):
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[tool.sanity]\n'
        'exclude_override = ["only_this/**"]\n'
    )
    cfg = load_config(str(tmp_path))
    assert cfg.exclude_patterns == ["only_this/**"]
    assert "test_*.py" not in cfg.exclude_patterns


# -- IGNORE_MARKER constant --


def test_ignore_marker_value():
    assert IGNORE_MARKER == "# sanity: ignore"


# -- save_to_sanityrc and CLI tests --

from click.testing import CliRunner
from sanity.cli import main
from sanity.config import save_to_sanityrc


def test_save_to_sanityrc(tmp_path):
    save_to_sanityrc("deletion_ratio_threshold", 4.0, str(tmp_path))
    save_to_sanityrc("disabled_checks", ["a", "b"], str(tmp_path))
    
    rc_path = tmp_path / ".sanityrc"
    assert rc_path.exists()
    content = rc_path.read_text(encoding="utf-8")
    assert "deletion_ratio_threshold = 4.0" in content
    assert 'disabled_checks = ["a", "b"]' in content
    
    cfg = load_config(str(tmp_path))
    assert cfg.deletion_ratio_threshold == 4.0
    assert cfg.disabled_checks == ["a", "b"]
    

def test_save_to_sanityrc_fresh_file(tmp_path):
    # User requirement: on a fresh .sanityrc, only the explicitly set key should be written, never defaults.
    from sanity.config import save_to_sanityrc
    
    save_to_sanityrc("entropy_threshold", 4.0, str(tmp_path))
    
    rc_path = tmp_path / ".sanityrc"
    content = rc_path.read_text(encoding="utf-8").strip()
    
    # It should only contain the single key we set
    assert content == "entropy_threshold = 4.0"
    assert "deletion_ratio_threshold" not in content


def test_cli_config_display(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["config"])
    assert result.exit_code == 0
    assert "--- Sanity Configuration ---" in result.output
    assert "deletion_ratio_threshold: 3.0" in result.output
    

def test_cli_config_set(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["config", "--set", "deletion_ratio_threshold=5.5"])
    assert result.exit_code == 0
    assert "Success: set deletion_ratio_threshold = 5.5" in result.output
    
    rc_path = tmp_path / ".sanityrc"
    assert "deletion_ratio_threshold = 5.5" in rc_path.read_text()
    
    result = runner.invoke(main, ["config", "--set", "disabled_checks=foo, bar"])
    assert result.exit_code == 0
    assert "Success: set disabled_checks = ['foo', 'bar']" in result.output
