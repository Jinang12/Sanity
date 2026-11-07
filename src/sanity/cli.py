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
        if task_desc:
            click.echo("Running LLM scope check...")
            llm_result = check_scope(diff_result, task_desc)
            if llm_result:
                results.append(llm_result)
        else:
            click.echo("\nScope check skipped: no task description provided (use --task).")

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


@main.command()
def init() -> None:
    """Install Sanity as a git pre-commit hook."""
    import stat
    import shutil
    
    git_dir = Path(".git")
    if not git_dir.is_dir():
        click.echo("Error: Not a git repository. Run this inside a git repo.")
        raise SystemExit(1)
        
    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(exist_ok=True)
    
    hook_path = hooks_dir / "pre-commit"
    if hook_path.exists():
        content = hook_path.read_text(encoding="utf-8")
        if "sanity check" in content:
            click.echo("Sanity pre-commit hook is already installed.")
            return
        
        click.echo("Warning: A pre-commit hook already exists.")
        if click.confirm("Do you want to back it up (to pre-commit.backup) and overwrite it?"):
            shutil.copy2(hook_path, hook_path.with_name("pre-commit.backup"))
        else:
            click.echo("Aborted.")
            raise SystemExit(1)
            
    import sys
    
    executable = sys.executable.replace("\\", "/")
    hook_script = f"#!/usr/bin/env bash\n# Sanity Pre-Commit Hook\n\n\"{executable}\" -m sanity.cli check\nif [ $? -ne 0 ]; then\n    exit 1\nfi\n"
    hook_path.write_text(hook_script, encoding="utf-8")
    
    # Make executable
    st = os.stat(hook_path)
    os.chmod(hook_path, st.st_mode | stat.S_IEXEC)
    
    click.echo("Success: Sanity pre-commit hook installed at .git/hooks/pre-commit")


@main.command()
@click.option("--set", "set_val", type=str, help="Set a config value, e.g. deletion_ratio_threshold=4.0")
def config(set_val: str | None) -> None:
    """View or update Sanity configuration."""
    from sanity.config import load_config, save_to_sanityrc, DEFAULT_EXCLUDE_PATTERNS
    
    if set_val:
        if "=" not in set_val:
            click.echo("Error: Invalid format. Use --set key=value")
            raise SystemExit(1)
            
        key, val = set_val.split("=", 1)
        key = key.strip()
        val = val.strip()
        
        valid_keys = {"exclude", "exclude_override", "disabled_checks", "deletion_ratio_threshold", "entropy_threshold"}
        if key not in valid_keys:
            click.echo(f"Error: Unknown configuration key '{key}'. Valid keys are: {', '.join(valid_keys)}")
            raise SystemExit(1)
            
        parsed_val: any = val
        if key in ("deletion_ratio_threshold", "entropy_threshold"):
            try:
                parsed_val = float(val)
            except ValueError:
                click.echo(f"Error: '{val}' is not a valid number for {key}.")
                raise SystemExit(1)
        elif key in ("exclude", "exclude_override", "disabled_checks"):
            parsed_val = [x.strip() for x in val.split(",") if x.strip()]
            
        save_to_sanityrc(key, parsed_val)
        click.echo(f"Success: set {key} = {parsed_val} in .sanityrc")
        return

    cfg = load_config()
    click.echo("--- Sanity Configuration ---")
    click.echo(f"deletion_ratio_threshold: {cfg.deletion_ratio_threshold}")
    click.echo(f"entropy_threshold: {cfg.entropy_threshold}")
    click.echo(f"disabled_checks: {cfg.disabled_checks}")
    click.echo(f"exclude_patterns: {cfg.exclude_patterns}")
    if cfg.exclude_patterns != DEFAULT_EXCLUDE_PATTERNS:
        click.echo("(Overrides are active)")
    else:
        click.echo("(Using default exclude patterns)")


if __name__ == "__main__":
    main()
