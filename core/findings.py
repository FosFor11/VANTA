# core/findings.py
# VANTA 1.0 — Findings storage

from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime


@dataclass
class Finding:
    severity: str          # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    description: str
    module: str
    timestamp: str = field(default_factory=lambda: datetime.now().strftime("%H:%M:%S"))


class FindingsManager:
    """Хранилище всех находок"""

    def __init__(self):
        self.items: List[Finding] = []
        self.counts: Dict[str, int] = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }

    def add(self, severity: str, title: str, description: str, module: str):
        severity = severity.upper()
        if severity not in self.counts:
            severity = "INFO"

        finding = Finding(
            severity=severity,
            title=title,
            description=description,
            module=module
        )
        self.items.append(finding)
        self.counts[severity] += 1
        return finding

    def clear(self):
        self.items.clear()
        for key in self.counts:
            self.counts[key] = 0

    def get_counts(self) -> Dict[str, int]:
        return self.counts.copy()

    def get_all(self) -> List[Finding]:
        return self.items.copy()