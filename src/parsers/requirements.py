import re
from pathlib import Path
from dataclasses import dataclass

@dataclass
class Dependency:
    name: str
    version: str | None
    raw: str

def parse_requirements(file_path: Path) -> list[Dependency]:
    dependencies = []
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('-'):
                continue
            
            dep = parse_line(line)
            if dep:
                dependencies.append(dep)
    
    return dependencies

def parse_line(line: str) -> Dependency | None:
    # Patterns: requests==2.28.0, requests>=2.0, requests~=2.0, requests
    pattern = r'^([a-zA-Z0-9_-]+)([<>=!~]+)?(.+)?$'
    match = re.match(pattern, line.split(';')[0].strip())
    
    if match:
        name = match.group(1)
        version = match.group(3).strip() if match.group(3) else None
        return Dependency(name=name, version=version, raw=line)
    
    return None
