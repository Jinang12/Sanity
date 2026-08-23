import click

from sanity import __version__


@click.group()
@click.version_option(version=__version__, prog_name="sanity")
def main() -> None:
    """Sanity — pre-commit risk checker for AI-generated code."""


import os
from pathlib import Path

@main.command()
@click.option("--task", type=str, help="The task description for the LLM scope check.")
@click.option("--force", is_flag=True, help="Override HIGH risk block and allow commit.")
def check(task: str | None, force: bool) -> None:
    """Run safety checks on the current staged diff."""
    from sanity.checks import run_all_checks
    from sanity.config import load_config
    from sanity.diff import get_staged_diff
    from sanity.display import print_check_results, print_diff_summary, print_final_decision
    from sanity.llm_check import check_scope
    from sanity.scorer import calculate_risk, log_override

    diff_result = get_staged_diff()
    if not diff_result.files:
        click.echo("No staged changes found. Stage some files first.")
        raise SystemExit(0)
    print_diff_summary(diff_result)

    config = load_config()
    results = run_all_checks(diff_result, config=config)
    
    # Check if any static check failed HIGH
    has_high_failure = any(not r.passed and r.severity == "HIGH" for r in results)
    
    if not has_high_failure:
        task_desc = task
        if not task_desc:
            commit_msg_path = Path(".git/COMMIT_EDITMSG")
            if commit_msg_path.exists():
                try:
                    content = commit_msg_path.read_text(encoding="utf-8").strip()
                    if content and not content.startswith("#"):
                        task_desc = content
                except Exception:
                    pass
                    
        if task_desc:
            click.echo("Running LLM scope check...")
            llm_result = check_scope(diff_result, task_desc)
            if llm_result:
                results.append(llm_result)
        else:
            click.echo("\nScope check skipped: no task description provided (use --task or a commit message).")

    print_check_results(results)

    risk = calculate_risk(results)
    failed_checks = [r for r in results if not r.passed]
    high_checks = [r.check_name for r in failed_checks if r.severity == "HIGH"]

    if risk == "HIGH" and force:
        log_override(diff_result, high_checks)
        
    print_final_decision(risk, force, high_checks)

    if risk == "HIGH" and not force:
        raise SystemExit(1)

    from sanity.snapshot import create_snapshot
    create_snapshot(diff_result, risk)


@main.command()
@click.argument("identifier", required=False)
@click.option("--list", "list_only", is_flag=True, help="List recent snapshots.")
@click.option("--prune", is_flag=True, help="Remove snapshots older than 30 days.")
def rollback(identifier: str | None, list_only: bool, prune: bool) -> None:
    """List, restore, or prune git snapshots created by Sanity."""
    from sanity.snapshot import list_snapshots, prune_snapshots, rollback_snapshot

    if prune:
        prune_snapshots()
        return

    if list_only or not identifier:
        list_snapshots()
        return

    rollback_snapshot(identifier)


if __name__ == "__main__":
    main()
