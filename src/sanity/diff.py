import os
import re

from git import Repo, InvalidGitRepositoryError

from sanity.models import DiffResult, FileDiff


def find_repo(path: str | None = None) -> Repo:
    target = path or os.getcwd()
    try:
        return Repo(target, search_parent_directories=True)
    except InvalidGitRepositoryError:
        raise SystemExit(f"Error: '{target}' is not inside a git repository.")


def parse_diff_text(diff_text: str) -> tuple[int, int]:
    added = 0
    deleted = 0
    for line in diff_text.splitlines():
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            deleted += 1
    return added, deleted


def _parse_raw_diff_to_files(raw_diff: str) -> list[FileDiff]:
    if not raw_diff.strip():
        return []

    files: list[FileDiff] = []
    # Split on "diff --git" boundaries
    chunks = re.split(r"^diff --git ", raw_diff, flags=re.MULTILINE)

    for chunk in chunks:
        if not chunk.strip():
            continue

        # Extract file path from "a/path b/path" header
        header_match = re.match(r"a/(.*?) b/(.*)", chunk.split("\n")[0])
        if not header_match:
            continue

        file_path = header_match.group(2)
        is_new = "new file mode" in chunk
        is_deleted = "deleted file mode" in chunk

        renamed_match = re.search(r"rename from (.*)", chunk)
        is_renamed = renamed_match is not None
        rename_from = renamed_match.group(1) if renamed_match else None

        added, deleted = parse_diff_text(chunk)

        files.append(FileDiff(
            path=file_path,
            added_lines=added,
            deleted_lines=deleted,
            is_new=is_new,
            is_deleted=is_deleted,
            is_renamed=is_renamed,
            rename_from=rename_from,
            diff_text=chunk,
        ))

    return files


def get_staged_diff(repo_path: str | None = None) -> DiffResult:
    repo = find_repo(repo_path)
    result = DiffResult()

    # Capture the full raw diff text (works even before first commit)
    try:
        result.raw_diff = repo.git.diff("--cached")
    except Exception:
        result.raw_diff = ""

    # Try using GitPython's structured diff against HEAD
    has_head = True
    try:
        repo.head.commit
    except (ValueError, TypeError):
        has_head = False

    if has_head:
        staged = repo.index.diff("HEAD", create_patch=True, R=True)
        for d in staged:
            diff_text = d.diff.decode("utf-8", errors="replace") if isinstance(d.diff, bytes) else str(d.diff)
            file_path = d.b_path or d.a_path or "unknown"
            added, deleted = parse_diff_text(diff_text)

            file_diff = FileDiff(
                path=file_path,
                added_lines=added,
                deleted_lines=deleted,
                is_new=d.new_file,
                is_deleted=d.deleted_file,
                is_renamed=d.renamed_file,
                rename_from=d.rename_from if d.renamed_file else None,
                diff_text=diff_text,
            )
            result.files.append(file_diff)
            result.total_added += added
            result.total_deleted += deleted
    else:
        # No HEAD yet (initial commit) — parse raw diff output
        result.files = _parse_raw_diff_to_files(result.raw_diff)
        result.total_added = sum(f.added_lines for f in result.files)
        result.total_deleted = sum(f.deleted_lines for f in result.files)

    return result

