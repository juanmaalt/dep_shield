import pytest
from pathlib import Path

from src.parsers.requirements import Dependency, parse_line, parse_requirements


class TestParseLine:
    def test_pinned_version(self):
        dep = parse_line("requests==2.28.0")
        assert dep is not None
        assert dep.name == "requests"
        assert dep.version == "2.28.0"
        assert dep.raw == "requests==2.28.0"

    def test_gte_version(self):
        dep = parse_line("flask>=2.0.0")
        assert dep is not None
        assert dep.name == "flask"
        assert dep.version == "2.0.0"

    def test_compatible_release(self):
        dep = parse_line("numpy~=1.21.0")
        assert dep is not None
        assert dep.name == "numpy"
        assert dep.version == "1.21.0"

    def test_no_version(self):
        dep = parse_line("requests")
        assert dep is not None
        assert dep.name == "requests"
        assert dep.version is None

    def test_strips_environment_markers(self):
        dep = parse_line("requests==2.28.0; python_version>='3.8'")
        assert dep is not None
        assert dep.name == "requests"
        assert dep.version == "2.28.0"

    def test_empty_string_returns_none(self):
        dep = parse_line("")
        assert dep is None

    def test_hyphen_name(self):
        dep = parse_line("my-package==1.0.0")
        assert dep is not None
        assert dep.name == "my-package"
        assert dep.version == "1.0.0"

    def test_underscored_name(self):
        dep = parse_line("my_package>=2.0")
        assert dep is not None
        assert dep.name == "my_package"
        assert dep.version == "2.0"

    def test_raw_field_preserved(self):
        raw = "requests==2.28.0"
        dep = parse_line(raw)
        assert dep.raw == raw


class TestParseRequirements:
    def test_parses_standard_file(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("requests==2.28.0\nflask>=2.0.0\nnumpy\n")

        deps = parse_requirements(req_file)
        assert len(deps) == 3
        assert deps[0].name == "requests"
        assert deps[1].name == "flask"
        assert deps[2].name == "numpy"

    def test_skips_comments(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("# this is a comment\nrequests==2.28.0\n")

        deps = parse_requirements(req_file)
        assert len(deps) == 1
        assert deps[0].name == "requests"

    def test_skips_empty_lines(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("\n\nrequests==2.28.0\n\n")

        deps = parse_requirements(req_file)
        assert len(deps) == 1

    def test_skips_options(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("-r other.txt\n-e .\nrequests==2.28.0\n")

        deps = parse_requirements(req_file)
        assert len(deps) == 1

    def test_empty_file(self, tmp_path):
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("")

        deps = parse_requirements(req_file)
        assert deps == []
