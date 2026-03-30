"""Baseline diff — compare current scan against a previous scan.

Classifies every finding as new, fixed, or persistent by matching on
the same (title, severity, location) key used by dedup.
"""

import json
from dataclasses import dataclass, field

from webscan.dedup import _dedup_key, deduplicate
from webscan.models import Finding, Severity


@dataclass
class DiffResult:
    new: list[Finding] = field(default_factory=list)
    fixed: list[Finding] = field(default_factory=list)
    persistent: list[Finding] = field(default_factory=list)

    def summary(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "persistent": len(self.persistent),
        }

    def to_dict(self) -> dict:
        return {
            "new": [f.to_dict() for f in self.new],
            "fixed": [f.to_dict() for f in self.fixed],
            "persistent": [f.to_dict() for f in self.persistent],
        }


def load_baseline(path: str) -> list[Finding]:
    """Load findings from a previous webscan JSON report.

    Uses ``deduped_findings`` when present, otherwise extracts from
    ``module_results[].findings[]`` and deduplicates.
    """
    with open(path) as f:
        data = json.load(f)

    if "deduped_findings" in data and data["deduped_findings"]:
        return [Finding.from_dict(d) for d in data["deduped_findings"]]

    # Fallback: reconstruct from per-module results
    findings: list[Finding] = []
    for mr in data.get("module_results", []):
        for fd in mr.get("findings", []):
            findings.append(Finding.from_dict(fd))

    return deduplicate(findings)


def compute_diff(baseline: list[Finding], current: list[Finding]) -> DiffResult:
    """Compare *current* findings against *baseline*.

    Returns a ``DiffResult`` with:
    - **new**: in current but not in baseline
    - **fixed**: in baseline but not in current
    - **persistent**: in both (uses current scan's finding object)
    """
    baseline_map = {_dedup_key(f): f for f in baseline}
    current_map = {_dedup_key(f): f for f in current}

    baseline_keys = set(baseline_map)
    current_keys = set(current_map)

    def _sorted(findings: list[Finding]) -> list[Finding]:
        return sorted(findings, key=lambda f: (-Severity.rank(f.severity), f.title.lower()))

    new = _sorted([current_map[k] for k in current_keys - baseline_keys])
    fixed = _sorted([baseline_map[k] for k in baseline_keys - current_keys])
    persistent = _sorted([current_map[k] for k in current_keys & baseline_keys])

    return DiffResult(new=new, fixed=fixed, persistent=persistent)
