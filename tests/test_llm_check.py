import os
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from sanity.cli import main
from sanity.llm_check import check_scope, summarize_diff
from sanity.models import CheckResult, DiffResult, FileDiff


def test_summarize_diff():
    diff = DiffResult(
        files=[
            FileDiff(
                path="src/main.py",
                is_new=False,
                is_deleted=False,
                is_renamed=False,
                rename_from=None,
                added_lines=1,
                deleted_lines=1,
                diff_text="--- a/src/main.py\n+++ b/src/main.py\n@@ -1,3 +1,3 @@\n-old code\n+new code\n"
            )
        ],
        total_added=1,
        total_deleted=1,
    )
    summary = summarize_diff(diff)
    assert "File: src/main.py (+1 -1)" in summary
    assert "+new code" in summary
    assert "-old code" in summary


@patch("sanity.llm_check.Groq")
def test_check_scope_yes(mock_groq, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake_key")
    mock_client = MagicMock()
    mock_groq.return_value = mock_client
    
    mock_message = MagicMock()
    mock_message.message.content = "YES\nThe task is perfectly implemented."
    mock_client.chat.completions.create.return_value.choices = [mock_message]

    diff = DiffResult([], 0, 0)
    result = check_scope(diff, "do nothing")
    
    assert result is not None
    assert result.passed is True
    assert result.severity == "LOW"
    assert "The task is perfectly implemented" in result.reason


@patch("sanity.llm_check.Groq")
def test_check_scope_no(mock_groq, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake_key")
    mock_client = MagicMock()
    mock_groq.return_value = mock_client
    
    mock_message = MagicMock()
    mock_message.message.content = "NO\nThis deletes the database."
    mock_client.chat.completions.create.return_value.choices = [mock_message]

    diff = DiffResult([], 0, 0)
    result = check_scope(diff, "add a comment")
    
    assert result is not None
    assert result.passed is False
    assert result.severity == "HIGH"
    assert "NO: This deletes the database." in result.reason


@patch("sanity.llm_check.Groq")
def test_check_scope_unsure(mock_groq, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake_key")
    mock_client = MagicMock()
    mock_groq.return_value = mock_client
    
    mock_message = MagicMock()
    mock_message.message.content = "UNSURE\nI don't have enough context."
    mock_client.chat.completions.create.return_value.choices = [mock_message]

    diff = DiffResult([], 0, 0)
    result = check_scope(diff, "refactor")
    
    assert result is not None
    assert result.passed is False
    assert result.severity == "MEDIUM"
    assert "UNSURE: I don't have enough context." in result.reason


@patch("sanity.llm_check.Groq")
def test_check_scope_malformed(mock_groq, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake_key")
    mock_client = MagicMock()
    mock_groq.return_value = mock_client
    
    mock_message = MagicMock()
    mock_message.content = "I think it looks okay, but maybe not." # Not starting with YES/NO/UNSURE
    mock_choice = MagicMock()
    mock_choice.message = mock_message
    mock_choice.finish_reason = "stop"
    mock_client.chat.completions.create.return_value.choices = [mock_choice]

    diff = DiffResult([], 0, 0)
    result = check_scope(diff, "refactor")
    
    assert result is not None
    assert result.passed is False
    assert result.severity == "MEDIUM"
    assert "UNSURE" in result.reason


@patch("sanity.llm_check.Groq")
def test_check_scope_max_tokens_exceeded(mock_groq, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake_key")
    mock_client = MagicMock()
    mock_groq.return_value = mock_client
    
    mock_message = MagicMock()
    mock_message.content = "" # Empty content because of length
    mock_choice = MagicMock()
    mock_choice.message = mock_message
    mock_choice.finish_reason = "length"
    mock_client.chat.completions.create.return_value.choices = [mock_choice]

    diff = DiffResult([FileDiff("small_test.py", True, False, False, None, 5, 0, "+print('hello')")], 5, 0)
    result = check_scope(diff, "add print")
    
    assert result is not None
    assert result.passed is False
    assert result.severity == "MEDIUM"
    assert "UNSURE: Model returned empty response" in result.reason


@patch("sanity.llm_check.Groq")
def test_check_scope_api_error(mock_groq, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "fake_key")
    mock_client = MagicMock()
    mock_groq.return_value = mock_client
    
    mock_client.chat.completions.create.side_effect = Exception("API down")

    diff = DiffResult([], 0, 0)
    result = check_scope(diff, "refactor")
    
    assert result is None # Fails gracefully


@patch("sanity.llm_check.load_dotenv")
def test_check_scope_missing_api_key(mock_load, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    diff = DiffResult([], 0, 0)
    result = check_scope(diff, "refactor")
    assert result is None


@patch("sanity.diff.get_staged_diff")
@patch("sanity.llm_check.check_scope")
@patch("sanity.cli.Path")
def test_cli_skips_scope_when_no_task(mock_path, mock_check_scope, mock_get_diff):
    # Mocking diff with some changes so it doesn't exit early
    diff = DiffResult([FileDiff("a.py", False, False, False, None, 1, 0, "+a")], 1, 0)
    mock_get_diff.return_value = diff
    
    mock_path_instance = MagicMock()
    mock_path_instance.exists.return_value = False
    mock_path.return_value = mock_path_instance

    runner = CliRunner()
    result = runner.invoke(main, ["check"])
    
    # Static checks should pass, but LLM check skipped
    assert "Scope check skipped: no task description provided" in result.output
    mock_check_scope.assert_not_called()


@patch("sanity.diff.get_staged_diff")
@patch("sanity.llm_check.check_scope")
def test_cli_skips_scope_when_static_check_fails_high(mock_check_scope, mock_get_diff):
    # Create a diff that definitely triggers a HIGH static failure (pure deletion)
    diff = DiffResult([FileDiff("a.py", False, False, False, None, 0, 100, "-old")], 0, 100)
    mock_get_diff.return_value = diff

    runner = CliRunner()
    result = runner.invoke(main, ["check", "--task", "test"])
    
    assert result.exit_code == 1
    mock_check_scope.assert_not_called()


@patch("sanity.diff.get_staged_diff")
@patch("sanity.llm_check.check_scope")
def test_cli_runs_scope_with_task_arg(mock_check_scope, mock_get_diff):
    diff = DiffResult([FileDiff("a.py", False, False, False, None, 1, 0, "+a")], 1, 0)
    mock_get_diff.return_value = diff
    
    mock_check_scope.return_value = CheckResult("scope_verification", True, "LOW", "LGTM")

    runner = CliRunner()
    result = runner.invoke(main, ["check", "--task", "add file"])
    
    assert result.exit_code == 0
    assert "Running LLM scope check..." in result.output
    mock_check_scope.assert_called_once()
