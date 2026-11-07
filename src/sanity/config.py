import os
from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # type: ignore[no-redef]


IGNORE_MARKER = "# sanity: ignore"

DEFAULT_EXCLUDE_PATTERNS: list[str] = [
    "test_*.py",
    "*_test.py",
    "tests/**",
    "README*",
    "*.md",
    "docs/**",
    "CHANGELOG*",
    "examples/**",
    ".sanity/**",
]


@dataclass
class SanityConfig:
    exclude_patterns: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDE_PATTERNS))
    disabled_checks: list[str] = field(default_factory=list)
    deletion_ratio_threshold: float = 3.0
    entropy_threshold: float = 3.8

    def is_excluded(self, file_path: str) -> bool:
        normalized = file_path.replace("\\", "/").removeprefix("./")
        for pattern in self.exclude_patterns:
            pattern = pattern.replace("\\", "/").removeprefix("./")
            if fnmatch(normalized, pattern):
                return True
            # Support "tests/**" matching "tests/foo.py"
            if pattern.endswith("/**"):
                prefix = pattern[:-3]
                if normalized.startswith(prefix + "/") or normalized == prefix:
                    return True
        return False


def _load_from_pyproject(project_dir: str) -> dict:
    pyproject_path = Path(project_dir) / "pyproject.toml"
    if not pyproject_path.exists():
        return {}
    with open(pyproject_path, "rb") as f:
        data = tomllib.load(f)
    return data.get("tool", {}).get("sanity", {})


def _load_from_sanityrc(project_dir: str) -> dict:
    for name in (".sanityrc", ".sanityrc.toml"):
        rc_path = Path(project_dir) / name
        if rc_path.exists():
            with open(rc_path, "rb") as f:
                return tomllib.load(f)
    return {}


def load_config(project_dir: str | None = None) -> SanityConfig:
    project_dir = project_dir or os.getcwd()
    config = SanityConfig()

    # .sanityrc takes priority over pyproject.toml
    raw = _load_from_sanityrc(project_dir)
    if not raw:
        raw = _load_from_pyproject(project_dir)

    if not raw:
        return config

    if "exclude" in raw:
        extra = raw["exclude"]
        if isinstance(extra, list):
            config.exclude_patterns = list(DEFAULT_EXCLUDE_PATTERNS) + extra

    if "exclude_override" in raw:
        override = raw["exclude_override"]
        if isinstance(override, list):
            config.exclude_patterns = override

    if "disabled_checks" in raw:
        disabled = raw["disabled_checks"]
        if isinstance(disabled, list):
            config.disabled_checks = disabled

    if "deletion_ratio_threshold" in raw:
        try:
            config.deletion_ratio_threshold = float(raw["deletion_ratio_threshold"])
        except (ValueError, TypeError):
            pass

    if "entropy_threshold" in raw:
        try:
            config.entropy_threshold = float(raw["entropy_threshold"])
        except (ValueError, TypeError):
            pass

    return config


def save_to_sanityrc(key: str, value: any, project_dir: str | None = None) -> None:
    project_dir = project_dir or os.getcwd()
    
    rc_path = Path(project_dir) / ".sanityrc"
    for name in (".sanityrc", ".sanityrc.toml"):
        p = Path(project_dir) / name
        if p.exists():
            rc_path = p
            break
            
    raw = _load_from_sanityrc(project_dir)
    raw[key] = value
    
    lines = []
    for k, v in raw.items():
        if isinstance(v, list):
            formatted_list = ", ".join(f'"{str(item)}"' for item in v)
            lines.append(f"{k} = [{formatted_list}]")
        elif isinstance(v, float) or isinstance(v, int):
            lines.append(f"{k} = {v}")
        else:
            lines.append(f'{k} = "{str(v)}"')
            
    rc_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
