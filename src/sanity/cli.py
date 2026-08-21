import click

from sanity import __version__


@click.group()
@click.version_option(version=__version__, prog_name="sanity")
def main() -> None:
    """Sanity — pre-commit risk checker for AI-generated code."""


@main.command()
def check() -> None:
    """Run safety checks on the current staged diff."""
    from sanity.checks import run_all_checks
    from sanity.config import load_config
    from sanity.diff import get_staged_diff
    from sanity.display import print_check_results, print_diff_summary

    diff_result = get_staged_diff()
    if not diff_result.files:
        click.echo("No staged changes found. Stage some files first.")
        raise SystemExit(0)
    print_diff_summary(diff_result)

    config = load_config()
    results = run_all_checks(diff_result, config=config)
    print_check_results(results)

    failed = [r for r in results if not r.passed]
    if any(r.severity == "HIGH" for r in failed):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
