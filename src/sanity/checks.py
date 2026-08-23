import math
import re
from collections import Counter

from sanity.config import IGNORE_MARKER, SanityConfig
from sanity.models import CheckResult, DiffResult


def _extract_added_lines(
    diff: DiffResult,
    config: SanityConfig | None = None,
) -> list[tuple[str, str]]:
    """Extract added lines from diff, returning (file_path, line_content) pairs.

    Skips files matching exclusion patterns and lines with the inline ignore marker.
    """
    results = []
    for f in diff.files:
        if config and config.is_excluded(f.path):
            continue
        for line in f.diff_text.splitlines():
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                if IGNORE_MARKER in content:
                    continue
                results.append((f.path, content))
    return results


def check_deletion_ratio(diff: DiffResult, threshold: float = 3.0) -> CheckResult:
    if diff.total_added == 0 and diff.total_deleted == 0:
        return CheckResult(
            check_name="deletion_ratio",
            passed=True,
            severity="LOW",
            reason="No line changes to evaluate.",
        )

    if diff.total_added == 0:
        if diff.total_deleted > 0:
            return CheckResult(
                check_name="deletion_ratio",
                passed=False,
                severity="HIGH",
                reason=f"Pure deletion: {diff.total_deleted} lines deleted with 0 lines added.",
            )
        return CheckResult(
            check_name="deletion_ratio",
            passed=True,
            severity="LOW",
            reason="No meaningful changes.",
        )

    ratio = diff.total_deleted / diff.total_added
    if ratio > threshold:
        return CheckResult(
            check_name="deletion_ratio",
            passed=False,
            severity="HIGH",
            reason=(
                f"Deletion ratio {ratio:.1f}x exceeds threshold {threshold}x "
                f"({diff.total_deleted} deleted / {diff.total_added} added)."
            ),
        )

    return CheckResult(
        check_name="deletion_ratio",
        passed=True,
        severity="LOW",
        reason=f"Deletion ratio {ratio:.1f}x is within threshold {threshold}x.",
    )


SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("AWS secret key", re.compile(r"(?i)(aws_secret_access_key|aws_secret)\s*[=:]\s*\S{20,}")),
    ("Stripe API key", re.compile(r"(?i)(sk_live_|sk_test_|pk_live_|pk_test_)[A-Za-z0-9]{20,}")),
    ("Private key header", re.compile(r"-----BEGIN\s+(RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")),
    ("Generic API key assignment", re.compile(r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?")),
    ("Generic secret assignment", re.compile(r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?")),
    ("Generic token assignment", re.compile(r"(?i)(auth[_-]?token|access[_-]?token|token)\s*[=:]\s*['\"]?[A-Za-z0-9_\-]{16,}['\"]?")),
    ("Password assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?[^\s'\"]{8,}['\"]?")),
    ("Connection string", re.compile(r"(?i)(mysql|postgres|mongodb|redis)://\S+:\S+@")),
]


def check_secrets(
    diff: DiffResult,
    config: SanityConfig | None = None,
) -> CheckResult:
    added_lines = _extract_added_lines(diff, config)
    findings: list[str] = []

    for file_path, line in added_lines:
        for pattern_name, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(f"{pattern_name} in {file_path}")
                break  # one finding per line is enough

    if findings:
        detail = "; ".join(findings[:5])
        extra = f" (+{len(findings) - 5} more)" if len(findings) > 5 else ""
        return CheckResult(
            check_name="secret_detection",
            passed=False,
            severity="HIGH",
            reason=f"Potential secrets detected: {detail}{extra}",
        )

    return CheckResult(
        check_name="secret_detection",
        passed=True,
        severity="LOW",
        reason="No secrets detected in added lines.",
    )


DANGEROUS_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("rm -rf", re.compile(r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\s+--force|-[a-zA-Z]*f[a-zA-Z]*r)\b")),  # sanity: ignore
    ("DROP TABLE", re.compile(r"(?i)\bDROP\s+TABLE\b")),  # sanity: ignore
    ("DELETE without WHERE", re.compile(r"(?i)\bDELETE\s+FROM\s+\w+\s*;")),
    ("TRUNCATE", re.compile(r"(?i)\bTRUNCATE\s+(TABLE\s+)?\w+")),
    ("git force push", re.compile(r"git\s+push\s+.*(-f|--force)\b")),
    ("os.remove", re.compile(r"\bos\s*\.\s*remove\s*\(")),
    ("shutil.rmtree", re.compile(r"\bshutil\s*\.\s*rmtree\s*\(")),
]


def check_dangerous_commands(
    diff: DiffResult,
    config: SanityConfig | None = None,
) -> CheckResult:
    cfg = config or SanityConfig()
    findings: list[str] = []

    standard_patterns = [p for p in DANGEROUS_PATTERNS if p[0] != "DELETE without WHERE"]

    for f in diff.files:
        if cfg.is_excluded(f.path):
            continue

        lines = f.diff_text.splitlines()
        for i, line in enumerate(lines):
            if line.startswith("+") and not line.startswith("+++"):
                content = line[1:]
                if IGNORE_MARKER in content:
                    continue

                for pattern_name, pattern in standard_patterns:
                    if pattern.search(content):
                        findings.append(f"{pattern_name} in {f.path}")

                match = re.search(r"(?i)\bDELETE\s+FROM\s+\w+", content)
                if match:
                    has_where = False
                    if re.search(r"(?i)\bWHERE\b", content[match.end():]):
                        has_where = True
                    else:
                        for j in range(i + 1, min(i + 10, len(lines))):
                            next_line = lines[j]
                            if next_line.startswith(("-", "---")):
                                continue
                            if next_line.startswith(("+", " ")):
                                next_content = next_line[1:]
                                if re.search(r"(?i)\bWHERE\b", next_content):
                                    has_where = True
                                    break
                                if ";" in next_content:
                                    break
                    if not has_where:
                        findings.append(f"DELETE without WHERE in {f.path}")

    if findings:
        detail = "; ".join(findings[:5])
        extra = f" (+{len(findings) - 5} more)" if len(findings) > 5 else ""
        return CheckResult(
            check_name="dangerous_commands",
            passed=False,
            severity="HIGH",
            reason=f"Dangerous commands detected: {detail}{extra}",
        )

    return CheckResult(
        check_name="dangerous_commands",
        passed=True,
        severity="LOW",
        reason="No dangerous commands detected in added lines.",
    )


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freqs = Counter(s)
    entropy = 0.0
    for count in freqs.values():
        p = count / len(s)
        entropy -= p * math.log2(p)
    return entropy


def looks_like_high_entropy_secret(s: str, threshold: float = 3.8) -> bool:
    if len(s) < 20:
        return False
    if " " in s:
        return False

    lower = s.lower()
    placeholders = ["your", "here", "xxx", "changeme", "example", "placeholder", "insert", "dummy", "key", "token"]
    if any(p in lower for p in placeholders):
        return False

    return shannon_entropy(s) > threshold


def check_high_entropy_secrets(
    diff: DiffResult,
    config: SanityConfig | None = None,
) -> CheckResult:
    cfg = config or SanityConfig()
    added_lines = _extract_added_lines(diff, cfg)
    findings: list[str] = []

    threshold = cfg.entropy_threshold

    pattern = re.compile(
        r"(?i)(?:['\"]?)\b([a-z0-9_]*(?:key|token|secret|password|credential|api|auth)[a-z0-9_]*)\b(?:['\"]?)\s*[=:]\s*(['\"])([^'\"]{20,})\2"
    )

    for file_path, line in added_lines:
        if any(p.search(line) for _, p in SECRET_PATTERNS):
            continue

        for match in pattern.finditer(line):
            val = match.group(3)
            if looks_like_high_entropy_secret(val, threshold):
                var_name = match.group(1)
                findings.append(f"High entropy secret ({var_name}) in {file_path}")
                break

    if findings:
        detail = "; ".join(findings[:5])
        extra = f" (+{len(findings) - 5} more)" if len(findings) > 5 else ""
        return CheckResult(
            check_name="high_entropy_secrets",
            passed=False,
            severity="HIGH",
            reason=f"Potential high-entropy secrets detected: {detail}{extra}",
        )

    return CheckResult(
        check_name="high_entropy_secrets",
        passed=True,
        severity="LOW",
        reason="No high-entropy secrets detected.",
    )


def run_all_checks(
    diff: DiffResult,
    config: SanityConfig | None = None,
) -> list[CheckResult]:
    cfg = config or SanityConfig()
    results: list[CheckResult] = []

    if "deletion_ratio" not in cfg.disabled_checks:
        results.append(check_deletion_ratio(diff, threshold=cfg.deletion_ratio_threshold))

    if "secret_detection" not in cfg.disabled_checks:
        results.append(check_secrets(diff, config=cfg))

    if "high_entropy_secrets" not in cfg.disabled_checks:
        results.append(check_high_entropy_secrets(diff, config=cfg))

    if "dangerous_commands" not in cfg.disabled_checks:
        results.append(check_dangerous_commands(diff, config=cfg))

    return results
