from sanity.models import FileDiff, DiffResult, CheckResult


def test_file_diff_net_change():
    fd = FileDiff(path="foo.py", added_lines=10, deleted_lines=3)
    assert fd.net_change == 7


def test_file_diff_defaults():
    fd = FileDiff(path="bar.py")
    assert fd.added_lines == 0
    assert fd.deleted_lines == 0
    assert fd.is_new is False
    assert fd.is_deleted is False
    assert fd.is_renamed is False
    assert fd.rename_from is None
    assert fd.diff_text == ""


def test_diff_result_totals():
    dr = DiffResult(
        files=[
            FileDiff(path="a.py", added_lines=5, deleted_lines=2),
            FileDiff(path="b.py", added_lines=3, deleted_lines=1),
        ],
        total_added=8,
        total_deleted=3,
    )
    assert dr.total_files == 2
    assert dr.net_change == 5


def test_diff_result_empty():
    dr = DiffResult()
    assert dr.total_files == 0
    assert dr.net_change == 0


def test_check_result():
    cr = CheckResult(
        check_name="secret_detection",
        passed=False,
        severity="HIGH",
        reason="AWS access key detected in config.py",
    )
    assert cr.check_name == "secret_detection"
    assert cr.passed is False
    assert cr.severity == "HIGH"
