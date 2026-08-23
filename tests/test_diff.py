import os
import tempfile
from pathlib import Path

from git import Repo

from sanity.diff import get_staged_diff, parse_diff_text, find_repo


def _make_test_repo(tmp_path: str) -> Repo:
    repo = Repo.init(tmp_path)
    repo.config_writer().set_value("user", "name", "Test").release()
    repo.config_writer().set_value("user", "email", "test@test.com").release()
    return repo


def test_parse_diff_text_counts():
    diff = """--- a/file.py
+++ b/file.py
@@ -1,3 +1,4 @@
 import os
-import sys
+import pathlib
+import json
 unchanged line"""
    added, deleted = parse_diff_text(diff)
    assert added == 2
    assert deleted == 1


def test_parse_diff_text_empty():
    added, deleted = parse_diff_text("")
    assert added == 0
    assert deleted == 0


def test_get_staged_diff_no_changes(tmp_path):
    tmp = str(tmp_path)
    _make_test_repo(tmp)
    result = get_staged_diff(tmp)
    assert result.total_files == 0
    assert result.files == []


def test_get_staged_diff_new_file(tmp_path):
    tmp = str(tmp_path)
    repo = _make_test_repo(tmp)

    # Create and stage a new file
    test_file = Path(tmp) / "hello.py"
    test_file.write_text("print('hello')\nprint('world')\n")
    repo.index.add(["hello.py"])

    result = get_staged_diff(tmp)
    assert result.total_files == 1
    assert result.files[0].path == "hello.py"
    assert result.files[0].added_lines == 2
    assert result.files[0].deleted_lines == 0
    assert result.files[0].is_new is True


def test_get_staged_diff_modified_file(tmp_path):
    tmp = str(tmp_path)
    repo = _make_test_repo(tmp)

    # Create, commit, then modify and stage
    test_file = Path(tmp) / "app.py"
    test_file.write_text("line1\nline2\nline3\n")
    repo.index.add(["app.py"])
    repo.index.commit("initial")

    test_file.write_text("line1\nmodified_line2\nline3\nnew_line4\n")
    repo.index.add(["app.py"])

    result = get_staged_diff(tmp)
    assert result.total_files == 1
    assert result.files[0].path == "app.py"
    assert result.files[0].added_lines >= 1
    assert result.files[0].deleted_lines >= 1
    assert result.files[0].is_new is False


def test_get_staged_diff_deleted_file(tmp_path):
    tmp = str(tmp_path)
    repo = _make_test_repo(tmp)

    # Create, commit, then delete and stage
    test_file = Path(tmp) / "remove_me.py"
    test_file.write_text("to be deleted\n")
    repo.index.add(["remove_me.py"])
    repo.index.commit("add file")

    os.remove(str(test_file))
    repo.index.remove(["remove_me.py"])

    result = get_staged_diff(tmp)
    assert result.total_files == 1
    assert result.files[0].is_deleted is True
    assert result.files[0].deleted_lines >= 1


def test_get_staged_diff_multiple_files(tmp_path):
    tmp = str(tmp_path)
    repo = _make_test_repo(tmp)

    for name in ["a.py", "b.py", "c.txt"]:
        (Path(tmp) / name).write_text(f"content of {name}\n")
    repo.index.add(["a.py", "b.py", "c.txt"])

    result = get_staged_diff(tmp)
    assert result.total_files == 3
    paths = {f.path for f in result.files}
    assert paths == {"a.py", "b.py", "c.txt"}
    assert result.total_added == 3
