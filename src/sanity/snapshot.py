import json
import time
from datetime import datetime, timezone
from pathlib import Path

import click
from git import Repo

from sanity.diff import find_repo
from sanity.models import DiffResult

SNAPSHOT_PREFIX = "sanity-snapshot-"
SNAPSHOTS_FILE = Path(".sanity/snapshots.jsonl")


def create_snapshot(diff: DiffResult, risk_level: str) -> None:
    try:
        repo = find_repo()
        # repo.head.is_valid() handles initial commit cases gracefully
        if not repo.head.is_valid():
            return

        now = datetime.now(timezone.utc)
        base_name = f"{SNAPSHOT_PREFIX}{now.strftime('%Y%m%d-%H%M%S')}"
        tag_name = base_name

        # Handle tag collisions if generated in the same second
        counter = 1
        while tag_name in repo.tags:
            tag_name = f"{base_name}-{counter}"
            counter += 1

        repo.create_tag(tag_name)

        SNAPSHOTS_FILE.parent.mkdir(parents=True, exist_ok=True)

        entry = {
            "timestamp": now.timestamp(),
            "tag": tag_name,
            "files_changed": [f.path for f in diff.files],
            "risk_level": risk_level,
        }
        with open(SNAPSHOTS_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")

    except Exception as e:
        click.secho(f"Warning: Failed to create snapshot: {e}", fg="yellow", err=True)


def read_snapshots() -> list[dict]:
    if not SNAPSHOTS_FILE.exists():
        return []

    snapshots = []
    with open(SNAPSHOTS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    snapshots.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return snapshots


def write_snapshots(snapshots: list[dict]) -> None:
    SNAPSHOTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(SNAPSHOTS_FILE, "w", encoding="utf-8") as f:
        for s in snapshots:
            f.write(json.dumps(s) + "\n")


def list_snapshots() -> None:
    snapshots = read_snapshots()
    if not snapshots:
        click.echo("No snapshots found.")
        return

    snapshots.sort(key=lambda x: x.get("timestamp", 0), reverse=True)

    click.secho("--- Sanity Snapshots ---", bold=True, fg="cyan")
    for i, s in enumerate(snapshots[:10], start=1):
        dt = datetime.fromtimestamp(s.get("timestamp", 0), tz=timezone.utc).astimezone()
        dt_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        files = s.get("files_changed", [])
        files_str = f"{len(files)} files" if len(files) > 3 else ", ".join(files)
        risk = s.get("risk_level", "UNKNOWN")
        click.echo(f"{i}. [{dt_str}] {s['tag']} (Risk: {risk}, Changes: {files_str})")


def rollback_snapshot(identifier: str) -> None:
    snapshots = read_snapshots()
    if not snapshots:
        click.echo("No snapshots found.")
        return

    snapshots.sort(key=lambda x: x.get("timestamp", 0), reverse=True)

    target = None
    if identifier.isdigit():
        idx = int(identifier)
        if 1 <= idx <= len(snapshots):
            target = snapshots[idx - 1]
    else:
        for s in snapshots:
            if s.get("tag") == identifier:
                target = s
                break

    if not target:
        click.secho(f"Error: Snapshot '{identifier}' not found.", fg="red", err=True)
        return

    tag_name = target["tag"]
    repo = find_repo()

    if tag_name not in repo.tags:
        click.secho(f"Error: Git tag '{tag_name}' does not exist in the repository.", fg="red", err=True)
        return

    try:
        commits_to_undo = list(repo.iter_commits(f"{tag_name}..HEAD"))
    except Exception:
        commits_to_undo = []

    click.secho(f"Preparing to roll back to snapshot: {tag_name}", fg="yellow", bold=True)
    if commits_to_undo:
        click.echo(f"This will permanently discard the following {len(commits_to_undo)} commit(s):")
        for c in commits_to_undo:
            msg = c.message.split("\n")[0]
            click.echo(f"  - {c.hexsha[:7]} {msg}")
    else:
        click.echo("Working tree will be reset to the exact commit when the snapshot was taken.")

    click.secho("\nWARNING: This uses `git reset --hard`.", fg="red", bold=True)
    click.secho("Any uncommitted changes in your working directory will be PERMANENTLY LOST.", fg="red", bold=True)

    if click.confirm("Are you sure you want to proceed?"):
        try:
            repo.git.reset("--hard", tag_name)
            click.secho(f"Successfully rolled back to {tag_name}.", fg="green", bold=True)
        except Exception as e:
            click.secho(f"Error during rollback: {e}", fg="red", err=True)
    else:
        click.echo("Rollback cancelled.")


def prune_snapshots() -> None:
    snapshots = read_snapshots()
    if not snapshots:
        click.echo("No snapshots to prune.")
        return

    now = time.time()
    thirty_days = 30 * 24 * 3600

    kept = []
    pruned = []

    repo = find_repo()

    for s in snapshots:
        if now - s.get("timestamp", 0) > thirty_days:
            pruned.append(s)
            tag_name = s.get("tag")
            if tag_name and tag_name in repo.tags:
                try:
                    repo.delete_tag(tag_name)
                except Exception as e:
                    click.secho(f"Warning: Failed to delete git tag {tag_name}: {e}", fg="yellow", err=True)
        else:
            kept.append(s)

    if pruned:
        write_snapshots(kept)
        click.secho(f"Pruned {len(pruned)} snapshot(s) older than 30 days.", fg="green", bold=True)
    else:
        click.echo("No snapshots older than 30 days found.")
