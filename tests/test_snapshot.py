import json
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

from click.testing import CliRunner

from sanity.cli import main
from sanity.models import DiffResult, FileDiff
from sanity.snapshot import (
    SNAPSHOT_PREFIX,
    create_snapshot,
    list_snapshots,
    prune_snapshots,
    read_snapshots,
    rollback_snapshot,
    write_snapshots,
)


@patch("sanity.snapshot.find_repo")
def test_create_snapshot_handles_collision(mock_find_repo, tmp_path, monkeypatch):
    monkeypatch.setattr("sanity.snapshot.SNAPSHOTS_FILE", tmp_path / "snapshots.jsonl")
    
    mock_repo = MagicMock()
    mock_repo.head.is_valid.return_value = True
    
    # We mock it so that the base tag already exists, forcing the loop to append "-1"
    # The base tag will be whatever datetime.now() produces.
    # To reliably mock `in repo.tags`, we can use a side_effect or custom __contains__.
    # Actually, repo.tags is usually an iterable of TagReference, but checking `in repo.tags`
    # converts the string to check if a tag by that name exists if it's evaluated against a list of strings,
    # or GitPython's IterableList handles `in` by string name.
    # Let's mock `__contains__` on whatever `repo.tags` is.
    class MockTags:
        def __contains__(self, item):
            return not item.endswith("-1")
    
    mock_repo.tags = MockTags()
    mock_find_repo.return_value = mock_repo
    
    diff = DiffResult([FileDiff("test.py", True, False, False, None, 1, 0, "")], 1, 0)
    
    create_snapshot(diff, "LOW")
    
    assert mock_repo.create_tag.called
    created_tag_args = mock_repo.create_tag.call_args[0][0]
    assert created_tag_args.endswith("-1")
    
    snapshots = read_snapshots()
    assert len(snapshots) == 1
    assert snapshots[0]["tag"] == created_tag_args
    assert snapshots[0]["risk_level"] == "LOW"
    assert snapshots[0]["files_changed"] == ["test.py"]


@patch("sanity.snapshot.find_repo")
def test_create_snapshot_ignores_invalid_head(mock_find_repo, tmp_path, monkeypatch):
    monkeypatch.setattr("sanity.snapshot.SNAPSHOTS_FILE", tmp_path / "snapshots.jsonl")
    
    mock_repo = MagicMock()
    mock_repo.head.is_valid.return_value = False
    mock_find_repo.return_value = mock_repo
    
    diff = DiffResult([], 0, 0)
    create_snapshot(diff, "LOW")
    
    assert not mock_repo.create_tag.called
    assert len(read_snapshots()) == 0


def test_list_snapshots_empty_and_populated(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr("sanity.snapshot.SNAPSHOTS_FILE", tmp_path / "snapshots.jsonl")
    
    runner = CliRunner()
    result = runner.invoke(main, ["rollback"])
    assert "No snapshots found." in result.output
    
    now = time.time()
    write_snapshots([
        {"timestamp": now - 100, "tag": "sanity-snapshot-old", "files_changed": ["a.py"], "risk_level": "LOW"},
        {"timestamp": now, "tag": "sanity-snapshot-new", "files_changed": ["b.py", "c.py"], "risk_level": "MEDIUM"}
    ])
    
    result = runner.invoke(main, ["rollback"])
    assert "--- Sanity Snapshots ---" in result.output
    # Order should be newest first
    assert "1. [" in result.output
    assert "sanity-snapshot-new" in result.output
    assert "(Risk: MEDIUM, Changes: b.py, c.py)" in result.output
    assert "sanity-snapshot-old" in result.output


@patch("sanity.snapshot.find_repo")
def test_rollback_snapshot_aborted(mock_find_repo, tmp_path, monkeypatch):
    monkeypatch.setattr("sanity.snapshot.SNAPSHOTS_FILE", tmp_path / "snapshots.jsonl")
    now = time.time()
    write_snapshots([{"timestamp": now, "tag": "sanity-snapshot-1", "files_changed": ["a.py"], "risk_level": "LOW"}])
    
    mock_repo = MagicMock()
    mock_repo.tags = ["sanity-snapshot-1"]
    mock_find_repo.return_value = mock_repo
    
    runner = CliRunner()
    result = runner.invoke(main, ["rollback", "1"], input="N\n")
    
    assert "Preparing to roll back to snapshot: sanity-snapshot-1" in result.output
    assert "Rollback cancelled." in result.output
    assert not mock_repo.git.reset.called


@patch("sanity.snapshot.find_repo")
def test_rollback_snapshot_confirmed_by_number(mock_find_repo, tmp_path, monkeypatch):
    monkeypatch.setattr("sanity.snapshot.SNAPSHOTS_FILE", tmp_path / "snapshots.jsonl")
    now = time.time()
    write_snapshots([{"timestamp": now, "tag": "sanity-snapshot-1", "files_changed": ["a.py"], "risk_level": "LOW"}])
    
    mock_repo = MagicMock()
    mock_repo.tags = ["sanity-snapshot-1"]
    mock_find_repo.return_value = mock_repo
    
    runner = CliRunner()
    result = runner.invoke(main, ["rollback", "1"], input="y\n")
    
    assert "Successfully rolled back to sanity-snapshot-1." in result.output
    mock_repo.git.reset.assert_called_once_with("--hard", "sanity-snapshot-1")


@patch("sanity.snapshot.find_repo")
def test_rollback_snapshot_not_found(mock_find_repo, tmp_path, monkeypatch):
    monkeypatch.setattr("sanity.snapshot.SNAPSHOTS_FILE", tmp_path / "snapshots.jsonl")
    now = time.time()
    write_snapshots([{"timestamp": now, "tag": "sanity-snapshot-1", "files_changed": ["a.py"], "risk_level": "LOW"}])
    runner = CliRunner()
    result = runner.invoke(main, ["rollback", "99"])
    assert "Error: Snapshot '99' not found." in result.output


@patch("sanity.snapshot.find_repo")
def test_prune_snapshots(mock_find_repo, tmp_path, monkeypatch):
    monkeypatch.setattr("sanity.snapshot.SNAPSHOTS_FILE", tmp_path / "snapshots.jsonl")
    now = time.time()
    thirty_days = 30 * 24 * 3600
    
    write_snapshots([
        {"timestamp": now, "tag": "keep-me"},
        {"timestamp": now - thirty_days - 100, "tag": "delete-me"}
    ])
    
    mock_repo = MagicMock()
    mock_repo.tags = ["delete-me"]
    mock_find_repo.return_value = mock_repo
    
    runner = CliRunner()
    result = runner.invoke(main, ["rollback", "--prune"])
    
    assert "Pruned 1 snapshot(s) older than 30 days." in result.output
    mock_repo.delete_tag.assert_called_once_with("delete-me")
    
    remaining = read_snapshots()
    assert len(remaining) == 1
    assert remaining[0]["tag"] == "keep-me"
