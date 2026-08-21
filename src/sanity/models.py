from dataclasses import dataclass, field


@dataclass
class FileDiff:
    path: str
    added_lines: int = 0
    deleted_lines: int = 0
    is_new: bool = False
    is_deleted: bool = False
    is_renamed: bool = False
    rename_from: str | None = None
    diff_text: str = ""

    @property
    def net_change(self) -> int:
        return self.added_lines - self.deleted_lines


@dataclass
class DiffResult:
    files: list[FileDiff] = field(default_factory=list)
    total_added: int = 0
    total_deleted: int = 0
    raw_diff: str = ""

    @property
    def total_files(self) -> int:
        return len(self.files)

    @property
    def net_change(self) -> int:
        return self.total_added - self.total_deleted


@dataclass
class CheckResult:
    check_name: str
    passed: bool
    severity: str  # LOW, MEDIUM, HIGH
    reason: str
