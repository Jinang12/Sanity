import re
import warnings
from dataclasses import dataclass, field
from importlib import resources

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


GENERIC_RULE_IDS = {"generic-api-key"}


@dataclass(frozen=True)
class GitleaksRule:
    id: str
    description: str
    regex: re.Pattern[str] | None = None
    path: re.Pattern[str] | None = None
    keywords: list[str] = field(default_factory=list)
    entropy: float | None = None
    secret_group: int = 1
    severity: str = "HIGH"
    allowlist_regexes: list[re.Pattern[str]] = field(default_factory=list)
    allowlist_stopwords: list[str] = field(default_factory=list)
    allowlist_paths: list[re.Pattern[str]] = field(default_factory=list)


@dataclass(frozen=True)
class GlobalAllowlist:
    regexes: list[re.Pattern[str]] = field(default_factory=list)
    stopwords: list[str] = field(default_factory=list)
    paths: list[re.Pattern[str]] = field(default_factory=list)


def _compile_patterns(raw_list: list[str]) -> list[re.Pattern[str]]:
    compiled = []
    for pattern in raw_list:
        try:
            pattern = _translate_go_regex(pattern)
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FutureWarning)
                compiled.append(re.compile(pattern))
        except re.error:
            pass
    return compiled


def _translate_go_regex(pattern: str) -> str:
    """Translate common Go RE2 syntax to Python re syntax."""
    # 1. Translate Go RE2 \z (end of text) to Python \Z
    pattern = pattern.replace(r"\z", r"\Z")

    # 2. If pattern already starts with (?i), any subsequent (?i) is redundant
    if pattern.startswith("(?i)"):
        return "(?i)" + pattern[4:].replace("(?i)", "")

    # 3. Handle (?i)(?:... -> (?i:...
    pattern = pattern.replace("(?i)(?:", "(?i:")

    # 4. Handle Go flag reset (?-i:...) -> Python non-capturing group (?:...)
    pattern = re.sub(r'\(\?-[imsx]+:', '(?:', pattern)

    # 5. Handle mid-pattern (?i) by scoping it into a (?i:...) group
    while "(?i)" in pattern:
        idx = pattern.find("(?i)")
        if idx == 0:
            break

        # Count open parentheses before idx (ignoring escaped chars and character classes)
        open_paren_depth = 0
        escaped = False
        in_char_class = False
        i = 0
        while i < idx:
            c = pattern[i]
            if escaped:
                escaped = False
            elif c == '\\':
                escaped = True
            elif c == '[' and not in_char_class:
                in_char_class = True
            elif c == ']' and in_char_class:
                in_char_class = False
            elif not in_char_class:
                if c == '(':
                    open_paren_depth += 1
                elif c == ')':
                    open_paren_depth -= 1
            i += 1

        if open_paren_depth > 0:
            # Inside an enclosing group: find its closing ')'
            i = idx + 4
            inner_depth = 0
            escaped = False
            in_char_class = False
            close_idx = -1
            while i < len(pattern):
                c = pattern[i]
                if escaped:
                    escaped = False
                elif c == '\\':
                    escaped = True
                elif c == '[' and not in_char_class:
                    in_char_class = True
                elif c == ']' and in_char_class:
                    in_char_class = False
                elif not in_char_class:
                    if c == '(':
                        inner_depth += 1
                    elif c == ')':
                        if inner_depth == 0:
                            close_idx = i
                            break
                        else:
                            inner_depth -= 1
                i += 1

            if close_idx != -1:
                body = pattern[idx + 4 : close_idx]
                pattern = pattern[:idx] + f"(?i:{body})" + pattern[close_idx:]
            else:
                body = pattern[idx + 4:]
                pattern = pattern[:idx] + f"(?i:{body})"
        else:
            body = pattern[idx + 4:]
            pattern = pattern[:idx] + f"(?i:{body})"

    return pattern


def _parse_rules(data: dict) -> tuple[list[GitleaksRule], list[str], GlobalAllowlist]:
    rules: list[GitleaksRule] = []
    skipped: list[str] = []

    # Parse global allowlist
    global_al = data.get("allowlist", {})
    global_allowlist = GlobalAllowlist(
        regexes=_compile_patterns(global_al.get("regexes", [])),
        stopwords=[s.lower() for s in global_al.get("stopwords", [])],
        paths=_compile_patterns(global_al.get("paths", [])),
    )

    for raw_rule in data.get("rules", []):
        rule_id = raw_rule.get("id", "<unknown>")
        regex_str = raw_rule.get("regex")
        path_str = raw_rule.get("path")

        if regex_str is None and path_str is None:
            skipped.append(rule_id)
            continue

        compiled_regex = None
        if regex_str is not None:
            regex_str = _translate_go_regex(regex_str)
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", FutureWarning)
                    compiled_regex = re.compile(regex_str)
            except re.error:
                skipped.append(rule_id)
                continue

        compiled_path = None
        if path_str is not None:
            path_str = _translate_go_regex(path_str)
            try:
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", FutureWarning)
                    compiled_path = re.compile(path_str)
            except re.error:
                skipped.append(rule_id)
                continue

        # Parse per-rule allowlists (can be a list of allowlist objects)
        al_regexes: list[re.Pattern[str]] = []
        al_stopwords: list[str] = []
        al_paths: list[re.Pattern[str]] = []
        for al in raw_rule.get("allowlists", []):
            al_regexes.extend(_compile_patterns(al.get("regexes", [])))
            al_stopwords.extend(s.lower() for s in al.get("stopwords", []) if isinstance(s, str))
            al_paths.extend(_compile_patterns(al.get("paths", [])))

        rule_severity = "MEDIUM" if rule_id in GENERIC_RULE_IDS else "HIGH"
        rules.append(GitleaksRule(
            id=rule_id,
            description=raw_rule.get("description", ""),
            regex=compiled_regex,
            path=compiled_path,
            keywords=[k.lower() for k in raw_rule.get("keywords", [])],
            entropy=raw_rule.get("entropy"),
            secret_group=raw_rule.get("secretGroup", 1),
            severity=rule_severity,
            allowlist_regexes=al_regexes,
            allowlist_stopwords=al_stopwords,
            allowlist_paths=al_paths,
        ))

    return rules, skipped, global_allowlist


# Module-level cache
_cached_rules: list[GitleaksRule] | None = None
_cached_skipped: list[str] | None = None
_cached_global_allowlist: GlobalAllowlist | None = None


def load_rules() -> list[GitleaksRule]:
    global _cached_rules, _cached_skipped, _cached_global_allowlist
    if _cached_rules is not None:
        return _cached_rules

    toml_file = resources.files("sanity.data").joinpath("gitleaks_rules.toml")
    data = tomllib.loads(toml_file.read_text(encoding="utf-8"))

    _cached_rules, _cached_skipped, _cached_global_allowlist = _parse_rules(data)
    return _cached_rules


def get_skipped_ids() -> list[str]:
    load_rules()
    return _cached_skipped or []


def get_global_allowlist() -> GlobalAllowlist:
    load_rules()
    return _cached_global_allowlist or GlobalAllowlist()


def _reset_cache() -> None:
    """For testing only."""
    global _cached_rules, _cached_skipped, _cached_global_allowlist
    _cached_rules = None
    _cached_skipped = None
    _cached_global_allowlist = None
