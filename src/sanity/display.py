import click

from sanity.models import CheckResult, DiffResult


def print_diff_summary(diff: DiffResult) -> None:
    click.echo()
    click.secho("+------------------------------------------+", fg="cyan")
    click.secho("|       SANITY -- Staged Diff Summary       |", fg="cyan", bold=True)
    click.secho("+------------------------------------------+", fg="cyan")
    click.echo()

    click.echo(f"  Files changed:  {diff.total_files}")
    click.secho(f"  Lines added:    +{diff.total_added}", fg="green")
    click.secho(f"  Lines deleted:  -{diff.total_deleted}", fg="red")
    click.echo(f"  Net change:     {diff.net_change:+d}")
    click.echo()

    click.secho("  --- Files ---", fg="yellow")
    for f in diff.files:
        status = ""
        if f.is_new:
            status = click.style(" [NEW]", fg="green")
        elif f.is_deleted:
            status = click.style(" [DELETED]", fg="red")
        elif f.is_renamed:
            status = click.style(f" [RENAMED from {f.rename_from}]", fg="yellow")

        additions = click.style(f"+{f.added_lines}", fg="green")
        deletions = click.style(f"-{f.deleted_lines}", fg="red")
        click.echo(f"  {f.path}{status}  ({additions}, {deletions})")

    click.echo()


def print_check_results(results: list[CheckResult]) -> None:
    click.secho("+------------------------------------------+", fg="cyan")
    click.secho("|          Static Analysis Results          |", fg="cyan", bold=True)
    click.secho("+------------------------------------------+", fg="cyan")
    click.echo()

    for r in results:
        if r.passed:
            icon = click.style("PASS", fg="green", bold=True)
        elif r.severity == "HIGH":
            icon = click.style("FAIL", fg="red", bold=True)
        else:
            icon = click.style("WARN", fg="yellow", bold=True)

        click.echo(f"  [{icon}] {r.check_name}")
        click.echo(f"         {r.reason}")
        click.echo()

    passed = sum(1 for r in results if r.passed)
    failed = sum(1 for r in results if not r.passed)
    if failed == 0:
        click.secho(f"  All {passed} checks passed.", fg="green", bold=True)
    else:
        click.secho(f"  {failed} check(s) failed, {passed} passed.", fg="red", bold=True)
    click.echo()


def print_final_decision(risk: str, is_forced: bool, overridden_checks: list[str]) -> None:
    click.secho("+------------------------------------------+", fg="cyan")
    if risk == "LOW":
        click.secho("|       Overall risk: LOW -- commit allowed      |", fg="green", bold=True)
    elif risk == "MEDIUM":
        click.secho("|   Overall risk: MEDIUM -- commit allowed (see warnings)   |", fg="yellow", bold=True)
    else:
        if is_forced:
            click.secho("|  Overall risk: HIGH -- commit allowed (--force used)  |", fg="red", bold=True)
        else:
            click.secho("| Overall risk: HIGH -- commit blocked. Use --force to override |", fg="red", bold=True)
    click.secho("+------------------------------------------+", fg="cyan")
    click.echo()

    if risk == "HIGH" and is_forced:
        click.secho(f"WARNING: You have forcibly overridden the following HIGH risk failures: {', '.join(overridden_checks)}", fg="red", bold=True, bg="yellow")
        click.secho("This action has been logged for audit purposes.", fg="yellow")
        click.echo()

