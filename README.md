# Sanity

**Pre-commit risk checker for AI-generated code changes.**

Sanity sits between your AI coding agent (Claude Code, Cursor, Antigravity, etc.) and git, catching risky changes before they land.

## What it catches

- **Mass deletions** — flags commits that delete far more code than they add
- **Leaked secrets** — detects API keys, AWS credentials, private keys
- **Dangerous commands** — catches `rm -rf`, `DROP TABLE`, force-push scripts
- **Scope creep** — uses LLM analysis to verify changes match the stated task
- **Auto-snapshots** — every commit gets a safety snapshot for easy rollback

## Quick start

```bash
# Install
pip install -e .

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
| `sanity check` | Run safety checks on staged diff |
| `sanity rollback` | Revert to a previous safe snapshot |
| `sanity config` | Configure thresholds and toggle checks |

## Requirements

- Python 3.11+
- Git
- Groq API key (free, no credit card needed)
