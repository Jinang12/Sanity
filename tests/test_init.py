import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sanity.cli import main


def test_init_not_git_repo(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["init"])
    assert result.exit_code == 1
    assert "Error: Not a git repository" in result.output


def test_init_creates_hook(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".git").mkdir()
    
    runner = CliRunner()
    result = runner.invoke(main, ["init"])
    
    assert result.exit_code == 0
    assert "Success: Sanity pre-commit hook installed" in result.output
    
    hook_path = tmp_path / ".git" / "hooks" / "pre-commit"
    assert hook_path.exists()
    assert "sanity.cli check" in hook_path.read_text()
    
    # Check executable
    if os.name != "nt":
        st = os.stat(hook_path)
        assert st.st_mode & stat.S_IEXEC


def test_init_existing_hook_already_installed(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text("#!/bin/bash\nsanity check\n")
    
    runner = CliRunner()
    result = runner.invoke(main, ["init"])
    
    assert result.exit_code == 0
    assert "Sanity pre-commit hook is already installed" in result.output


def test_init_existing_hook_aborted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text("#!/bin/bash\necho other hook\n")
    
    runner = CliRunner()
    result = runner.invoke(main, ["init"], input="n\n")
    
    assert result.exit_code == 1
    assert "Aborted" in result.output
    assert not (hooks_dir / "pre-commit.backup").exists()


def test_init_existing_hook_backed_up(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True)
    hook_path = hooks_dir / "pre-commit"
    hook_path.write_text("#!/bin/bash\necho other hook\n")
    
    runner = CliRunner()
    result = runner.invoke(main, ["init"], input="y\n")
    
    assert result.exit_code == 0
    assert "Success" in result.output
    assert (hooks_dir / "pre-commit.backup").exists()
    assert (hooks_dir / "pre-commit.backup").read_text() == "#!/bin/bash\necho other hook\n"
