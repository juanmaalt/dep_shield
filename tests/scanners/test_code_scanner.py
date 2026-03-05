import pytest
from pathlib import Path

from src.scanners.code_scanner import find_python_files, scan_file_for_package, scan_project


class TestFindPythonFiles:
    def test_finds_python_files(self, tmp_path):
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("pass")

        files = find_python_files(tmp_path)
        assert len(files) == 2

    def test_empty_directory(self, tmp_path):
        assert find_python_files(tmp_path) == []

    def test_ignores_venv_directory(self, tmp_path):
        venv_dir = tmp_path / ".venv"
        venv_dir.mkdir()
        (venv_dir / "site.py").write_text("pass")
        (tmp_path / "main.py").write_text("pass")

        files = find_python_files(tmp_path)
        assert len(files) == 1
        assert all(".venv" not in str(f) for f in files)

    def test_ignores_pycache_directory(self, tmp_path):
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "module.pyc").write_text("")
        (tmp_path / "main.py").write_text("pass")

        files = find_python_files(tmp_path)
        assert len(files) == 1

    def test_nonexistent_directory_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            find_python_files(tmp_path / "nonexistent")

    def test_file_path_raises(self, tmp_path):
        file_path = tmp_path / "main.py"
        file_path.write_text("pass")

        with pytest.raises(NotADirectoryError):
            find_python_files(file_path)

    def test_finds_nested_files(self, tmp_path):
        subdir = tmp_path / "subpackage"
        subdir.mkdir()
        (subdir / "module.py").write_text("pass")
        (tmp_path / "main.py").write_text("pass")

        files = find_python_files(tmp_path)
        assert len(files) == 2

    def test_ignores_build_directory(self, tmp_path):
        build_dir = tmp_path / "build"
        build_dir.mkdir()
        (build_dir / "generated.py").write_text("pass")
        (tmp_path / "main.py").write_text("pass")

        files = find_python_files(tmp_path)
        assert len(files) == 1


class TestScanFileForPackage:
    def test_detects_direct_import(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests\n")

        usages = scan_file_for_package(py_file, "requests")
        assert len(usages) == 1
        assert usages[0].import_type == "import"
        assert usages[0].line_number == 1

    def test_detects_from_import(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("from requests import Session\n")

        usages = scan_file_for_package(py_file, "requests")
        assert len(usages) == 1
        assert usages[0].import_type == "from"

    def test_skips_comment_lines(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("# import requests\nimport os\n")

        usages = scan_file_for_package(py_file, "requests")
        assert len(usages) == 0

    def test_no_matches(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("import os\nimport sys\n")

        assert scan_file_for_package(py_file, "requests") == []

    def test_does_not_match_partial_name(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests_mock\n")

        usages = scan_file_for_package(py_file, "requests")
        assert len(usages) == 0

    def test_detects_submodule_import(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests.exceptions\n")

        usages = scan_file_for_package(py_file, "requests")
        assert len(usages) == 1
        assert usages[0].import_type == "import"

    def test_multiple_imports_in_file(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests\nfrom requests import Session\nprint('hello')\n")

        usages = scan_file_for_package(py_file, "requests")
        assert len(usages) == 2

    def test_line_content_recorded(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("from requests import Session\n")

        usages = scan_file_for_package(py_file, "requests")
        assert usages[0].line_content == "from requests import Session"

    def test_file_path_recorded(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("import requests\n")

        usages = scan_file_for_package(py_file, "requests")
        assert str(py_file) in usages[0].file_path

    def test_line_number_recorded(self, tmp_path):
        py_file = tmp_path / "app.py"
        py_file.write_text("import os\nimport requests\n")

        usages = scan_file_for_package(py_file, "requests")
        assert usages[0].line_number == 2


class TestScanProject:
    def test_scans_multiple_files(self, tmp_path):
        (tmp_path / "a.py").write_text("import requests\n")
        (tmp_path / "b.py").write_text("from requests import Session\n")
        (tmp_path / "c.py").write_text("import os\n")

        usages = scan_project(tmp_path, "requests")
        assert len(usages) == 2

    def test_empty_project(self, tmp_path):
        assert scan_project(tmp_path, "requests") == []

    def test_aggregates_from_nested_files(self, tmp_path):
        subdir = tmp_path / "sub"
        subdir.mkdir()
        (tmp_path / "main.py").write_text("import requests\n")
        (subdir / "helper.py").write_text("import requests\n")

        usages = scan_project(tmp_path, "requests")
        assert len(usages) == 2
