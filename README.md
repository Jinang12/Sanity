# Sanity - Pre-commit Risk Checker
[![PyPI version](https://img.shields.io/pypi/v/sanity-guard.svg)](https://pypi.org/project/sanity-guard/)

Sanity acts as a pre-commit risk checker for AI-generated code changes. It evaluates code additions for dangerous statements, exposed secrets, and scope drift, and safely blocks risky commits.

## Safety Nets & Snapshots
Whenever a commit is allowed (whether deemed safe, or overridden via `--force`), Sanity automatically creates a lightweight local git tag (e.g. `sanity-snapshot-20260823-153012`) pointing to the commit *before* the new changes. This ensures that even if an AI agent makes a destructive commit, you can easily view your history and roll it back using `sanity rollback <number>`.

> **Note**: `sanity-snapshot-*` tags are intended strictly as local safety nets. Git naturally keeps tags local during a standard `git push`, so they won't clutter your remote repository unless you explicitly run `git push --tags`.

## What it catches

- **Mass deletions** -- flags commits that delete far more code than they add
- **Leaked secrets** -- detects API keys, AWS credentials, private keys
- **Dangerous commands** -- catches `rm -rf`, `DROP TABLE`, force-push scripts
- **Scope creep** -- uses LLM analysis to verify changes match the stated task
- **Auto-snapshots** -- every commit gets a safety snapshot for easy rollback

## Quick start

```bash
# Install
pip install sanity-guard
```

> **Windows users**: if the `sanity` command isn't recognized after installing, pip may have installed it to a user Scripts directory that isn't on your PATH (pip's install output will show a warning with the exact path if this happens). Either run commands as `python -m sanity <command>` instead, or add that Scripts directory to your PATH.

```bash
# Set up your Groq API key (free tier)
cp .env.example .env
# Edit .env with your key from https://console.groq.com

# Install the pre-commit hook in your repo
sanity init

# Manually check staged changes
sanity check

# Rollback to a previous safe state
sanity rollback
```

## Commands

| Command | Description |
|---------|-------------|
| `sanity init` | Install pre-commit hook in current repo |
| `sanity check [--task "desc"] [--force]` | Run safety checks on staged diff |
| `sanity rollback [id] [--list] [--prune]` | Revert to a previous safe snapshot |
| `sanity config [--set key=val]` | Configure thresholds and toggle checks |

## How This Was Tested

- Stripe API keys were initially undetected by secret_detection -- found via manual adversarial testing, fixed by adding a dedicated regex pattern plus a generic Shannon-entropy fallback check for unknown/unlisted services (Firebase, Twilio, SendGrid, etc.)
- Multi-line DELETE FROM / WHERE statements bypassed dangerous_commands detection -- fixed by extending the check to scan forward across diff hunk context for a WHERE clause on a following line
- The LLM scope check intermittently returned empty responses -- root cause was the reasoning model (openai/gpt-oss-120b) consuming its entire max_tokens budget on internal reasoning before reaching a final answer; fixed by raising the token limit
- A test-isolation bug was found where running the test suite created real git tags and wrote to this project's actual .sanity/snapshots.jsonl file -- traced to CLI-level integration tests that weren't mocking snapshot creation; fixed by auditing and patching every test that invokes the CLI end-to-end
- GitHub's own secret-scanning push protection flagged realistic-looking fake keys in test fixtures when first pushing to GitHub -- resolved by rewriting fixtures to use obviously non-functional placeholder strings
- End-to-end verification: a real `git commit` containing a fake AWS key, run through the actual installed pre-commit hook (via `sanity init`), was correctly blocked by git itself -- not just `sanity check` reporting the right result when run manually
- The published PyPI package was verified by installing it in a completely fresh virtual environment with no access to the source repo, then confirming `sanity init` and a real blocked commit both worked correctly

## Known Limitations

**Detection is assignment-pattern-based, not content-based.** Both check_secrets and check_high_entropy_secrets only match code shaped like `variable_name = "value"` (or similar `:`/`=` syntax) where the variable name contains a suspicious keyword (key, token, secret, password, credential, api, auth). A secret-shaped string appearing any other way -- a bare string literal, a function call argument, text split across concatenated strings, embedded in a URL, or in a config format the regex doesn't anticipate -- will not be flagged, regardless of how random or sensitive it looks.

**Length and entropy thresholds create edge cases at the margins.** Known-pattern detection requires 16+ characters; the entropy fallback requires 20+ characters and a Shannon entropy above 3.8 bits/char. Very short secrets, or longer strings with heavy character repetition (lower measured entropy despite looking non-random), can fall under both thresholds. Confirmed during testing: a 37-character non-dictionary string scored 3.44 bits/char (just under threshold) due to repeated letters, while an equally long base64-style string scored 4.57 bits/char and was correctly caught.

**Scope verification requires manual task input.** The LLM scope check requires an explicit `--task` flag to run. Because git's `pre-commit` stage executes before the commit message is created, Sanity cannot automatically pull the commit message during a standard `git commit` -- the scope check will simply be skipped unless manually invoked.

This tool is a heuristic safety net designed to catch common, careless mistakes -- it does not replace purpose-built secret-scanning tools (e.g. TruffleHog, Gitleaks) or human code review.

## Requirements

- Python 3.11+
- Git
- Groq API key (free, no credit card needed)

## Development

Local development and publishing instructions for contributors:

```bash
# Local editable install
pip install -e .

# Build the package
python -m build

# Validate metadata
twine check dist/*

# Publish to PyPI
twine upload dist/*
```
