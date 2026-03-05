import tomllib
import re
from pathlib import Path

from src.parsers.requirements import Dependency, parse_line


def parse_pyproject(file_path: Path) -> list[Dependency]:
    with open(file_path, "rb") as f:
        data = tomllib.load(f)

    dependencies = []
    dependencies.extend(parse_pep621(data))
    dependencies.extend(parse_poetry(data))
    return dependencies


def parse_pep621(data: dict) -> list[Dependency]:
    raw_deps = data.get("project", {}).get("dependencies", [])
    deps = []
    for raw in raw_deps:
        dep = parse_line(raw)
        if dep:
            deps.append(dep)
    return deps


def parse_poetry(data: dict) -> list[Dependency]:
    raw_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    deps = []
    for name, constraint in raw_deps.items():
        if name.lower() == "python":
            continue
        version = extract_poetry_version(constraint)
        deps.append(Dependency(name=name, version=version, raw=f"{name} = {constraint!r}"))
    return deps


def extract_poetry_version(constraint) -> str | None:
    if isinstance(constraint, str):
        # Strip leading ^, ~, >=, etc. to get a bare version, or keep as-is
        return re.sub(r'^[\^~]', '', constraint) or None
    if isinstance(constraint, dict):
        version = constraint.get("version")
        if version:
            return re.sub(r'^[\^~]', '', version)
    return None
