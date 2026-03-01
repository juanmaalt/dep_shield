import re
from pathlib import Path
from dataclasses import dataclass

IGNORED_DIRS = {'.venv', 'venv', '__pycache__', '.git', 'node_modules', '.eggs', 'build', 'dist'}


@dataclass
class CodeUsage:
    file_path: str
    line_number: int
    line_content: str
    import_type: str

def find_python_files(directory: Path) -> list[Path]:
    if not directory.exists():
        raise FileNotFoundError(f"Directory not found: {directory}")
    
    if not directory.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {directory}")

    python_files = []
    for file_path in directory.rglob("*.py"):
        if any(ignored in file_path.parts for ignored in IGNORED_DIRS):
            continue
        
        python_files.append(file_path)
    
    return python_files

def scan_file_for_package(file_path: Path, package_name: str) -> list[CodeUsage]:
    pattern_a = rf"^import\s+{package_name}(\s|,|$|\.)"
    pattern_b = rf"^from\s+{package_name}(\s|\.)"
    result = []

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        for pos, line in enumerate(file, 1):
            line = line.strip()

            if line.startswith("#"):
                continue

            if re.match(pattern_a, line):
                import_type = "import"
            elif re.match(pattern_b, line):
                import_type = "from"
            else:
                continue

            result.append(
                CodeUsage(
                    file_path=str(file_path),
                    line_number=pos,
                    line_content=line,
                    import_type=import_type
                )
            )

    return result

def scan_project(directory: Path, package_name: str) -> list[CodeUsage]:
    file_paths = find_python_files(directory)
    result=[]

    for file_path in file_paths:
        usages = scan_file_for_package(file_path, package_name)
        result.extend(usages)

    return result