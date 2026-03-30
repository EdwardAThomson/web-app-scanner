"""Core data models for webscan findings and scan results."""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @staticmethod
    def rank(sev: "Severity") -> int:
        """Return numeric rank (higher = more severe)."""
        return {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[sev]


class Category(str, Enum):
    TLS = "tls"
    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"
    SECRET = "secret"
    DEPENDENCY = "dependency"
    CODE = "code"
    HEADER = "header"
    INJECTION = "injection"
    FUZZING = "fuzzing"
    AUTH = "auth"


@dataclass
class Finding:
    title: str
    severity: Severity
    category: Category
    source: str
    description: str
    location: str
    evidence: str = ""
    remediation: str = ""
    reference: str = ""
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["category"] = self.category.value
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Finding":
        """Reconstruct a Finding from a serialised dict (e.g. JSON report)."""
        return cls(
            title=d["title"],
            severity=Severity(d["severity"]),
            category=Category(d["category"]),
            source=d.get("source", ""),
            description=d.get("description", ""),
            location=d.get("location", ""),
            evidence=d.get("evidence", ""),
            remediation=d.get("remediation", ""),
            reference=d.get("reference", ""),
            metadata=d.get("metadata", {}),
        )


@dataclass
class ModuleResult:
    module_name: str
    success: bool
    findings: list[Finding] = field(default_factory=list)
    error: str = ""
    duration_seconds: float = 0.0
    tool_version: str = ""
    raw_output_path: str = ""

    def to_dict(self) -> dict:
        return {
            "module_name": self.module_name,
            "success": self.success,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "duration_seconds": self.duration_seconds,
            "tool_version": self.tool_version,
            "raw_output_path": self.raw_output_path,
        }


@dataclass
class ScanResult:
    target: str
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None
    module_results: list[ModuleResult] = field(default_factory=list)
    @property
    def all_findings(self) -> list[Finding]:
        findings = []
        for mr in self.module_results:
            findings.extend(mr.findings)
        return findings

    def summary(self) -> dict:
        by_severity: dict[str, int] = {}
        for f in self.all_findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
        return {
            "target": self.target,
            "total_findings": len(self.all_findings),
            "by_severity": by_severity,
            "modules_run": len(self.module_results),
            "modules_failed": sum(1 for m in self.module_results if not m.success),
        }

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "summary": self.summary(),
            "module_results": [mr.to_dict() for mr in self.module_results],
        }
