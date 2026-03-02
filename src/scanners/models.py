from dataclasses import dataclass


@dataclass
class Vulnerability:
    id: str
    summary: str
    severity: str | None
    details: str | None


@dataclass
class CodeUsage:
    file_path: str
    line_number: int
    line_content: str
    import_type: str
