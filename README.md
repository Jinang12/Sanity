# Sanity - Pre-commit Risk Checker
[![PyPI version](https://img.shields.io/pypi/v/sanity-guard.svg)](https://pypi.org/project/sanity-guard/)

Sanity acts as a pre-commit risk checker for AI-generated code changes. It evaluates code additions for dangerous statements, exposed secrets, and scope drift, and safely blocks risky commits.

## Safety Nets & Snapshots
Whenever a commit is allowed (whether deemed safe, or overridden via `--force`), Sanity automatically creates a lightweight local git tag (e.g. `sanity-snapshot-20260823-153012`) pointing to the commit *before* the new changes. This ensures that even if an AI agent makes a destructive commit, you can easily view your history and roll it back using `sanity rollback <number>`.

> **Note**: `sanity-snapshot-*` tags are intended strictly as local safety nets. Git naturally keeps tags local during a standard `git push`, so they won't clutter your remote repository unless you explicitly run `git push --tags`.

## What it catches

- **Leaked secrets** -- multi-layer detection: community-maintained Gitleaks rules, known format patterns, and Shannon entropy fallbacks
- **Mass deletions** -- flags commits that delete far more code than they add
- **Dangerous commands** -- catches `rm -rf`, `DROP TABLE`, force-push scripts
- **Scope creep** -- uses LLM analysis to verify changes match the stated task
- **Auto-snapshots** -- every commit gets a safety snapshot for easy rollback

## Secret Detection Architecture

Sanity employs a multi-tiered defense-in-depth model for secret detection:

1. **Known-Format Rules (Gitleaks)**: High-confidence signatures vendored and pinned directly from the [Gitleaks](https://github.com/gitleaks/gitleaks) project (MIT licensed). These community-maintained rules cover hundreds of service providers (GitHub, GitLab, Slack, AWS, OpenAI, etc.) and are not custom-written.
2. **Built-in Fast Patterns**: Rapid pattern-matching for core credentials (AWS keys, Stripe keys, private keys, database connection strings).
3. **Entropy Fallbacks (Tier 1 & Tier 2)**:
   - *Tier 1 (Keyword-gated)*: Flags high Shannon-entropy strings (> 3.8 bits/char, 20+ chars) assigned to suspicious variable names (`token`, `secret`, `password`, `key`, etc.) as HIGH risk.
   - *Tier 2 (Generic)*: Scans assignment-shaped lines for high entropy regardless of variable name (excluding UUIDs, hex hashes, and non-secret identifiers) as MEDIUM warning.
4. **Agent-Specific Safety Checks**: Dangerous command heuristics (`rm -rf`, `DROP TABLE`, DELETE without WHERE) and LLM-powered scope verification against the stated task.

## Quick start

```bash
# Install
pip install sanity-guard
```

> **Windows users**: if the `sanity` command isn't recognized after installing, pip may have installed it to a user Scripts directory that isn't on your PATH (pip's install output will show a warning with the exact path if this happens). Either run commands as `python -m sanity <command>` instead, or add that Scripts directory to your PATH.

```bash
# Set up your Groq API key (free tier)
# Set via environment variable (takes precedence) or in a .env file in cwd or git repo root:
export GROQ_API_KEY="your-api-key"
# Or:
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

**Go RE2 to Python regex compatibility.** Gitleaks rules are authored in Go RE2 regex syntax. Sanity translates Go-specific syntax (such as mid-pattern inline flags `(?i)` scoped to `(?i:...)`, flag resets, and end-of-text `\z` to `\Z`) so patterns compile accurately under Python's standard `re` module without altering matching behavior. All 222 rules from the vendored Gitleaks configuration are active (0 skipped). Any synthetic or future uncompilable rules are safely skipped without halting or crashing the tool.

**Detection is assignment-pattern-based, not content-based.** Both check_secrets and check_high_entropy_secrets only match code shaped like `variable_name = "value"` (or similar `:`/`=` syntax) where the variable name contains a suspicious keyword (key, token, secret, password, credential, api, auth). A secret-shaped string appearing any other way -- a bare string literal, a function call argument, text split across concatenated strings, embedded in a URL, or in a config format the regex doesn't anticipate -- will not be flagged, regardless of how random or sensitive it looks.

**Length and entropy thresholds create edge cases at the margins.** Known-pattern detection requires 16+ characters; the entropy fallback requires 20+ characters and a Shannon entropy above 3.8 bits/char. Very short secrets, or longer strings with heavy character repetition (lower measured entropy despite looking non-random), can fall under both thresholds. Confirmed during testing: a 37-character non-dictionary string scored 3.44 bits/char (just under threshold) due to repeated letters, while an equally long base64-style string scored 4.57 bits/char and was correctly caught.

**Scope verification requires manual task input.** The LLM scope check requires an explicit `--task` flag to run. Because git's `pre-commit` stage executes before the commit message is created, Sanity cannot automatically pull the commit message during a standard `git commit` -- the scope check will simply be skipped unless manually invoked.

**Concatenated strings can evade detection.** A secret split across concatenated string literals (`secret = "abc" + "def"`) can evade detection if each segment individually falls under the length threshold.

**Secrets passed as function arguments are not detected.** Secrets passed directly into function or method calls (such as `connect(api_key="...")` or `authenticate("secret-token")`) do not match assignment patterns and are not flagged by regex or entropy checks unless matched by a format-specific Gitleaks rule.

**Default exclusions omit test files and docs.** By default, `tests/**`, `test/**`, and `*.md` files are excluded from all checks, meaning secrets committed to test suites, fixtures, or markdown documentation are not scanned unless configured otherwise.

**`# sanity: ignore` bypasses every check.** Placing `# sanity: ignore` on any line suppresses all static safety checks for that line.

**Manual check runs create snapshot tags.** Running `sanity check` manually creates a safety snapshot git tag each time the staged changes are allowed (or forced), just like an automated pre-commit hook run.

This tool is a heuristic safety net designed to catch common, careless mistakes -- it does not replace purpose-built secret-scanning tools or human code review.

## Attribution & Licenses

Sanity vendors community-maintained secret detection rules from the [Gitleaks](https://github.com/gitleaks/gitleaks) project:
- **Gitleaks**: Licensed under the MIT License, Copyright (c) 2019 Zachary Rice.
- The pinned rules file (`gitleaks_rules.toml`) and the license text (`GITLEAKS_LICENSE`) are packaged in `src/sanity/data/`.

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
