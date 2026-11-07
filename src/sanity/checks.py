import math
import re
from collections import Counter
from pathlib import Path

from sanity.config import IGNORE_MARKER, SanityConfig
from sanity.gitleaks_rules import GitleaksRule, get_global_allowlist, load_rules
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
    ("Generic API key assignment", re.compile(r"(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?")),
    ("Generic secret assignment", re.compile(r"(?i)(secret[_-]?key|secret)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?")),
    ("Generic token assignment", re.compile(r"(?i)(auth[_-]?token|access[_-]?token|token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})['\"]?")),
    ("Password assignment", re.compile(r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"]?([^\s'\"]{8,})['\"]?")),
    ("Connection string", re.compile(r"(?i)(mysql|postgres|mongodb|redis)://\S+:\S+@")),
]

GENERIC_ASSIGNMENT_PATTERNS = {
    "Generic API key assignment",
    "Generic secret assignment",
    "Generic token assignment",
    "Password assignment",
}


def _is_generic_placeholder(val: str) -> bool:
    lower = val.lower()
    placeholder_patterns = [
        "your_", "_here", "xxx", "changeme", "example",
        "placeholder", "insert_", "dummy",
    ]
    if any(p in lower for p in placeholder_patterns):
        return True
    # Repeated single character (e.g. 'x' * 20, or repeated letters/symbols; preserve digits like 000...)
    if re.search(r"^([a-zA-Z\-_*#])\1{7,}$", val):
        return True
    return False


def _line_matches_secret_pattern(line: str, pattern_name: str, pattern: re.Pattern[str]) -> bool:
    m = pattern.search(line)
    if not m:
        return False
    if pattern_name in GENERIC_ASSIGNMENT_PATTERNS and m.lastindex and m.lastindex >= 2:
        val = m.group(2)
        if _is_generic_placeholder(val):
            return False
    return True


_SEVERITY_LEVELS: dict[str, int] = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}


def _can_skip_line(
    line_key: tuple[str, str],
    current_severity: str,
    flagged_lines: dict[tuple[str, str], str] | set[tuple[str, str]] | None,
) -> bool:
    if flagged_lines is None:
        return False
    if isinstance(flagged_lines, dict):
        prev_sev = flagged_lines.get(line_key)
        if prev_sev is None:
            return False
        return _SEVERITY_LEVELS.get(prev_sev, 0) >= _SEVERITY_LEVELS.get(current_severity, 0)
    elif isinstance(flagged_lines, set):
        return line_key in flagged_lines
    return False


def _record_flagged_line(
    line_key: tuple[str, str],
    severity: str,
    flagged_lines: dict[tuple[str, str], str] | set[tuple[str, str]] | None,
) -> None:
    if flagged_lines is None:
        return
    if isinstance(flagged_lines, dict):
        existing = flagged_lines.get(line_key)
        if existing is None or _SEVERITY_LEVELS.get(severity, 0) > _SEVERITY_LEVELS.get(existing, 0):
            flagged_lines[line_key] = severity
    elif isinstance(flagged_lines, set):
        flagged_lines.add(line_key)


def check_secrets(
    diff: DiffResult,
    config: SanityConfig | None = None,
    flagged_lines: dict[tuple[str, str], str] | set[tuple[str, str]] | None = None,
) -> CheckResult:
    cfg = config or SanityConfig()
    added_lines = _extract_added_lines(diff, cfg)
    findings: list[str] = []

    for file_path, line in added_lines:
        line_key = (file_path, line)
        if _can_skip_line(line_key, "HIGH", flagged_lines):
            continue

        for pattern_name, pattern in SECRET_PATTERNS:
            if _line_matches_secret_pattern(line, pattern_name, pattern):
                findings.append(f"{pattern_name} in {file_path}")
                _record_flagged_line(line_key, "HIGH", flagged_lines)
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
    ("TRUNCATE", re.compile(r"(?i)\bTRUNCATE\s+(?:TABLE\s+\w+|\w+\s*;)")),
    ("git force push", re.compile(r"\bgit\s+push\s+.*(-f|--force)\b")),
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
    placeholder_patterns = ["your_", "_here", "xxx", "changeme", "example", "placeholder", "insert_", "dummy"]
    if any(p in lower for p in placeholder_patterns):
        return False

    return shannon_entropy(s) > threshold


CONFIG_EXTENSIONS = {
    ".env", ".yaml", ".yml", ".ini", ".cfg", ".conf",
    ".properties", ".toml", ".sh",
}


def _is_config_file(file_path: str) -> bool:
    norm = file_path.replace("\\", "/")
    basename = norm.rsplit("/", 1)[-1]
    name_lower = basename.lower()

    dot_idx = basename.rfind(".")
    if dot_idx != -1:
        ext = basename[dot_idx:].lower()
        if ext in CONFIG_EXTENSIONS:
            return True
        if name_lower.startswith(".env"):
            return True
    else:
        if name_lower in ("dockerfile", "env"):
            return True

    return False


_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
_HEX_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{40}$|^[0-9a-f]{64}$", re.IGNORECASE)
_NON_SECRET_VARNAMES = re.compile(r"(?i)(?:^|_)(id|uuid|hash|checksum|sha|slug|filename|path|color|class|style)(?:_|$)")

_KEYWORD_QUOTED_PATTERN = re.compile(
    r"""(?i)(?:['"]?)"""
    r"""\b([a-z0-9_]*(?:key|token|secret|password|credential|api|auth)[a-z0-9_]*)\b"""
    r"""(?:['"]?)"""
    r"""\s*(?::\s*\w+\s*)?[=:]\s*(['"])([^'"]{20,})\2"""
)
_KEYWORD_UNQUOTED_PATTERN = re.compile(
    r"(?i)^\s*([a-z0-9_]*(?:key|token|secret|password|credential|api|auth)[a-z0-9_]*)\s*(?::\s*\w+\s*)?[=:]\s*([a-zA-Z0-9_\-\+\/\=\.]{20,})\s*$"
)

_GENERIC_QUOTED_PATTERN = re.compile(
    r"""(?i)(?:['"]?)"""
    r"""\b([a-z][a-z0-9_]*)\b"""
    r"""(?:['"]?)"""
    r"""\s*(?::\s*\w+\s*)?[=:]\s*(['"])([^'"]{20,})\2"""
)
_GENERIC_UNQUOTED_PATTERN = re.compile(
    r"(?i)^\s*([a-z][a-z0-9_]*)\s*(?::\s*\w+\s*)?[=:]\s*([a-zA-Z0-9_\-\+\/\=\.]{20,})\s*$"
)


def check_high_entropy_secrets(
    diff: DiffResult,
    config: SanityConfig | None = None,
    flagged_lines: dict[tuple[str, str], str] | set[tuple[str, str]] | None = None,
) -> CheckResult:
    cfg = config or SanityConfig()
    added_lines = _extract_added_lines(diff, cfg)
    findings: list[str] = []

    threshold = cfg.entropy_threshold

    for file_path, line in added_lines:
        line_key = (file_path, line)
        if _can_skip_line(line_key, "HIGH", flagged_lines):
            continue

        if "secret_detection" not in cfg.disabled_checks and _line_flagged_by_builtin_secrets(line):
            continue


        found = False
        for match in _KEYWORD_QUOTED_PATTERN.finditer(line):
            val = match.group(3)
            if looks_like_high_entropy_secret(val, threshold):
                var_name = match.group(1)
                findings.append(f"High entropy secret ({var_name}) in {file_path}")
                found = True
                _record_flagged_line(line_key, "HIGH", flagged_lines)
                break

        if not found and _is_config_file(file_path):
            m = _KEYWORD_UNQUOTED_PATTERN.match(line)
            if m:
                val = m.group(2)
                if looks_like_high_entropy_secret(val, threshold):
                    var_name = m.group(1)
                    findings.append(f"High entropy secret ({var_name}) in {file_path}")
                    _record_flagged_line(line_key, "HIGH", flagged_lines)

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


def _is_non_secret_identifier(val: str) -> bool:
    if _UUID_RE.match(val):
        return True
    if _HEX_HASH_RE.match(val):
        return True
    return False


def check_high_entropy_secrets_generic(
    diff: DiffResult,
    config: SanityConfig | None = None,
    flagged_lines: dict[tuple[str, str], str] | set[tuple[str, str]] | None = None,
) -> CheckResult:
    cfg = config or SanityConfig()
    added_lines = _extract_added_lines(diff, cfg)
    findings: list[str] = []

    threshold = cfg.entropy_threshold

    for file_path, line in added_lines:
        line_key = (file_path, line)
        if _can_skip_line(line_key, "MEDIUM", flagged_lines):
            continue

        if "secret_detection" not in cfg.disabled_checks and _line_flagged_by_builtin_secrets(line):
            continue


        found = False
        for match in _GENERIC_QUOTED_PATTERN.finditer(line):
            var_name = match.group(1)
            val = match.group(3)
            if _NON_SECRET_VARNAMES.search(var_name):
                continue
            if _is_non_secret_identifier(val):
                continue
            if looks_like_high_entropy_secret(val, threshold):
                findings.append(f"Possible secret ({var_name}) in {file_path}")
                found = True
                _record_flagged_line(line_key, "MEDIUM", flagged_lines)
                break

        if not found and _is_config_file(file_path):
            m = _GENERIC_UNQUOTED_PATTERN.match(line)
            if m:
                var_name = m.group(1)
                val = m.group(2)
                if not _NON_SECRET_VARNAMES.search(var_name) and not _is_non_secret_identifier(val):
                    if looks_like_high_entropy_secret(val, threshold):
                        findings.append(f"Possible secret ({var_name}) in {file_path}")
                        _record_flagged_line(line_key, "MEDIUM", flagged_lines)

    if findings:
        detail = "; ".join(findings[:5])
        extra = f" (+{len(findings) - 5} more)" if len(findings) > 5 else ""
        return CheckResult(
            check_name="high_entropy_secrets_generic",
            passed=False,
            severity="MEDIUM",
            reason=f"Possible high-entropy secrets (generic scan): {detail}{extra}",
        )

    return CheckResult(
        check_name="high_entropy_secrets_generic",
        passed=True,
        severity="LOW",
        reason="No high-entropy secrets detected (generic scan).",
    )


def _line_flagged_by_builtin_secrets(line: str) -> bool:
    return any(p.search(line) for _, p in SECRET_PATTERNS)


def _matches_allowlist(
    match_text: str,
    file_path: str,
    rule: GitleaksRule,
) -> bool:
    global_al = get_global_allowlist()

    # Global path patterns
    for path_re in global_al.paths:
        if path_re.search(file_path):
            return True

    # Per-rule path patterns
    for path_re in rule.allowlist_paths:
        if path_re.search(file_path):
            return True

    if match_text:
        # Global allowlist regexes
        for al_re in global_al.regexes:
            if al_re.search(match_text):
                return True

        # Global stopwords
        lower_match = match_text.lower()
        for sw in global_al.stopwords:
            if sw in lower_match:
                return True

        # Per-rule allowlist regexes
        for al_re in rule.allowlist_regexes:
            if al_re.search(match_text):
                return True

        # Per-rule stopwords
        for sw in rule.allowlist_stopwords:
            if sw in lower_match:
                return True

    return False


def check_gitleaks_rules(
    diff: DiffResult,
    config: SanityConfig | None = None,
    flagged_lines: dict[tuple[str, str], str] | set[tuple[str, str]] | None = None,
) -> CheckResult:
    cfg = config or SanityConfig()
    added_lines = _extract_added_lines(diff, cfg)
    findings: list[tuple[str, str, str]] = []
    rules = load_rules()

    for file_path, line in added_lines:
        line_key = (file_path, line)
        if _can_skip_line(line_key, "HIGH", flagged_lines):
            continue

        if "secret_detection" not in cfg.disabled_checks and _line_flagged_by_builtin_secrets(line):
            continue


        norm_path = file_path.replace("\\", "/")
        line_lower = line.lower()

        for rule in rules:
            if _can_skip_line(line_key, rule.severity, flagged_lines):
                continue

            if rule.path and not rule.path.search(norm_path):
                continue

            if rule.keywords and not any(kw in line_lower for kw in rule.keywords):
                continue

            if rule.regex:
                m = rule.regex.search(line)
                if not m:
                    continue

                if rule.secret_group <= (m.lastindex or 0):
                    matched_text = m.group(rule.secret_group)
                elif m.lastindex and m.lastindex >= 1:
                    matched_text = m.group(1)
                else:
                    matched_text = m.group(0)

                # Entropy threshold check
                if rule.entropy is not None:
                    if shannon_entropy(matched_text) < rule.entropy:
                        continue

                # Allowlist check
                if _matches_allowlist(matched_text, norm_path, rule):
                    continue
            elif rule.path:
                if _matches_allowlist("", norm_path, rule):
                    continue
            else:
                continue

            findings.append((rule.id, file_path, rule.severity))
            _record_flagged_line(line_key, rule.severity, flagged_lines)
            break  # one finding per line

    if findings:
        detail = "; ".join(f"{fid} in {fpath}" for fid, fpath, _ in findings[:5])
        extra = f" (+{len(findings) - 5} more)" if len(findings) > 5 else ""
        overall_severity = "HIGH" if any(sev == "HIGH" for _, _, sev in findings) else "MEDIUM"
        return CheckResult(
            check_name="gitleaks_rules",
            passed=False,
            severity=overall_severity,
            reason=f"Gitleaks rule match: {detail}{extra}",
        )

    return CheckResult(
        check_name="gitleaks_rules",
        passed=True,
        severity="LOW",
        reason="No gitleaks rule matches detected.",
    )


def run_all_checks(
    diff: DiffResult,
    config: SanityConfig | None = None,
) -> list[CheckResult]:
    cfg = config or SanityConfig()
    results: list[CheckResult] = []
    flagged_lines: dict[tuple[str, str], str] = {}

    if "deletion_ratio" not in cfg.disabled_checks:
        results.append(check_deletion_ratio(diff, threshold=cfg.deletion_ratio_threshold))

    if "secret_detection" not in cfg.disabled_checks:
        results.append(check_secrets(diff, config=cfg, flagged_lines=flagged_lines))

    if "gitleaks_rules" not in cfg.disabled_checks:
        results.append(check_gitleaks_rules(diff, config=cfg, flagged_lines=flagged_lines))

    if "high_entropy_secrets" not in cfg.disabled_checks:
        results.append(check_high_entropy_secrets(diff, config=cfg, flagged_lines=flagged_lines))

    if "high_entropy_secrets_generic" not in cfg.disabled_checks:
        results.append(check_high_entropy_secrets_generic(diff, config=cfg, flagged_lines=flagged_lines))

    if "dangerous_commands" not in cfg.disabled_checks:
        results.append(check_dangerous_commands(diff, config=cfg))

    return results

