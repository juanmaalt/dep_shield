from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel


@dataclass
class PackageInfo:
    name: str
    version: str | None

    def __str__(self) -> str:
        return f"{self.name} {self.version}".strip() if self.version else self.name


@dataclass
class SimilarCVE:
    id: str
    description: str
    metadata: str
    distance: float


class ImpactAnalysis(BaseModel):
    risk_level: Literal["HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
    explanation: str
    recommendation: str
