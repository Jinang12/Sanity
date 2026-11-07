import os
from pathlib import Path
import sys

from dotenv import load_dotenv
from groq import Groq, GroqError

from sanity.models import CheckResult, DiffResult

PROMPT_TEMPLATE = """You are a pre-commit risk analyzer. Your job is to verify that the staged changes only do what the task description specifies, and do not include unintended, unrelated, or potentially malicious modifications.

TASK DESCRIPTION:
{task}

STAGED CHANGES SUMMARY:
{diff_summary}

INSTRUCTIONS:
1. Does the diff plausibly implement the task and ONLY the task?
2. Respond with EXACTLY one of YES, NO, or UNSURE on the first line.
3. Provide exactly ONE sentence of reasoning on the second line.
4. Do not include any other text.
"""

def summarize_diff(diff: DiffResult) -> str:
    """Creates a token-efficient summary of the diff."""
    lines = []
    for f in diff.files:
        status = []
        if f.is_new: status.append("NEW")
        if f.is_deleted: status.append("DELETED")
        if f.is_renamed: status.append(f"RENAMED from {f.rename_from}")
        
        status_str = f" [{' '.join(status)}]" if status else ""
        lines.append(f"File: {f.path}{status_str} (+{f.added_lines} -{f.deleted_lines})")
        
        # Add actual changes but strip context to save tokens
        for line in f.diff_text.splitlines():
            if line.startswith(("+", "-")) and not line.startswith(("+++", "---")):
                # Truncate extremely long lines
                if len(line) > 120:
                    line = line[:117] + "..."
                lines.append(line)
        lines.append("") # blank line between files
        
    summary = "\n".join(lines).strip()
    # Hard limit on length to avoid huge diffs breaking the prompt limits
    if len(summary) > 8000:
        summary = summary[:8000] + "\n... [DIFF TRUNCATED FOR LENGTH]"
        
    return summary


def _load_groq_env() -> None:
    """Load .env from current working directory or git repo root, with override=False."""
    cwd = Path.cwd()
    env_file = cwd / ".env"
    if env_file.is_file():
        load_dotenv(dotenv_path=env_file, override=False)
        return

    curr = cwd
    while curr != curr.parent:
        if (curr / ".git").exists():
            git_env = curr / ".env"
            if git_env.is_file():
                load_dotenv(dotenv_path=git_env, override=False)
            return
        curr = curr.parent


def check_scope(diff: DiffResult, task_description: str) -> CheckResult | None:
    _load_groq_env()
    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print("Warning: Scope check skipped (GROQ_API_KEY not found in environment).", file=sys.stderr)
        return None

    client = Groq(api_key=api_key, timeout=10.0)
    
    diff_summary = summarize_diff(diff)
    prompt = PROMPT_TEMPLATE.format(task=task_description, diff_summary=diff_summary)

    try:
        completion = client.chat.completions.create(
            model="openai/gpt-oss-120b",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            max_tokens=1024,
        )
    except Exception as e:
        print(f"Warning: Scope check skipped due to API error ({e}).", file=sys.stderr)
        return None

    content = completion.choices[0].message.content or ""
    lines = [line.strip() for line in content.strip().splitlines() if line.strip()]
    
    if not lines:
        return CheckResult(
            check_name="scope_verification",
            passed=False,
            severity="MEDIUM",
            reason="UNSURE: Model returned empty response."
        )

    decision = lines[0].upper()
    reasoning = lines[1] if len(lines) > 1 else "No reasoning provided."

    if decision == "YES":
        return CheckResult(
            check_name="scope_verification",
            passed=True,
            severity="LOW",
            reason=reasoning
        )
    elif decision == "NO":
        return CheckResult(
            check_name="scope_verification",
            passed=False,
            severity="HIGH",
            reason=f"{decision}: {reasoning}"
        )
    else:
        # Treat UNSURE or any malformed response as UNSURE
        return CheckResult(
            check_name="scope_verification",
            passed=False,
            severity="MEDIUM",
            reason=f"UNSURE: {reasoning}"
        )
