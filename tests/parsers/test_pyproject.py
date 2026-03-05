import pytest
from pathlib import Path

from src.parsers.pyproject import extract_poetry_version, parse_pyproject


class TestExtractPoetryVersion:
    def test_caret_constraint(self):
        assert extract_poetry_version("^1.0.0") == "1.0.0"

    def test_curly_constraint(self):
        assert extract_poetry_version("~2.3.0") == "2.3.0"

    def test_plain_version(self):
        assert extract_poetry_version("1.0.0") == "1.0.0"

    def test_wildcard(self):
        assert extract_poetry_version("*") == "*"

    def test_dict_with_version(self):
        assert extract_poetry_version({"version": "^1.0.0"}) == "1.0.0"

    def test_dict_without_version_key(self):
        assert extract_poetry_version({"extras": ["security"]}) is None

    def test_dict_no_version(self):
        assert extract_poetry_version({}) is None


class TestParsePyproject:
    def test_pep621_format(self, tmp_path):
        content = (
            '[project]\nname = "myapp"\ndependencies = [\n'
            '    "requests>=2.0",\n'
            '    "flask==2.3.0",\n'
            "]\n"
        )
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_bytes(content.encode())

        deps = parse_pyproject(pyproject)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names

    def test_poetry_format(self, tmp_path):
        content = (
            "[tool.poetry.dependencies]\n"
            'python = "^3.12"\n'
            'requests = "^2.28.0"\n'
            'flask = {version = "^2.0", extras = ["async"]}\n'
        )
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_bytes(content.encode())

        deps = parse_pyproject(pyproject)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names
        assert "python" not in names

    def test_poetry_skips_python(self, tmp_path):
        content = (
            "[tool.poetry.dependencies]\n"
            'python = "^3.12"\n'
            'requests = "^2.28.0"\n'
        )
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_bytes(content.encode())

        deps = parse_pyproject(pyproject)
        assert all(d.name.lower() != "python" for d in deps)

    def test_empty_pyproject(self, tmp_path):
        content = '[project]\nname = "myapp"\nversion = "1.0"\n'
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_bytes(content.encode())

        deps = parse_pyproject(pyproject)
        assert deps == []

    def test_combines_pep621_and_poetry(self, tmp_path):
        content = (
            '[project]\ndependencies = ["requests>=2.0"]\n'
            "[tool.poetry.dependencies]\n"
            'flask = "^2.0"\n'
        )
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_bytes(content.encode())

        deps = parse_pyproject(pyproject)
        names = [d.name for d in deps]
        assert "requests" in names
        assert "flask" in names

    def test_pep621_versions_parsed(self, tmp_path):
        content = '[project]\ndependencies = ["numpy==1.21.0"]\n'
        pyproject = tmp_path / "pyproject.toml"
        pyproject.write_bytes(content.encode())

        deps = parse_pyproject(pyproject)
        assert len(deps) == 1
        assert deps[0].name == "numpy"
        assert deps[0].version == "1.21.0"
