"""Cross-module finding deduplication.

When multiple modules report the same underlying issue (e.g. "Missing
X-Frame-Options" from both headers and nuclei), this module consolidates
them into a single finding with all contributing sources tracked in
metadata.
"""

from webscan.models import Finding, Severity


def _dedup_key(finding: Finding) -> tuple[str, str, str]:
    """Return the grouping key for a finding.

    Findings are considered duplicates when they share the same title
    (case-insensitive), severity, and location.
    """
    return (finding.title.lower().strip(), finding.severity.value, finding.location.strip())


def _pick_best(findings: list[Finding]) -> Finding:
    """Merge a group of duplicate findings into one.

    Keeps the richest description/evidence/remediation and records all
    contributing sources.
    """
    sources = sorted({f.source for f in findings})

    # Pick the finding with the longest description as the base
    best = max(findings, key=lambda f: len(f.description))

    # Merge evidence — keep the longest
    evidence = max((f.evidence for f in findings), key=len)

    # Merge remediation — keep the longest
    remediation = max((f.remediation for f in findings), key=len)

    # Merge references — combine unique non-empty references
    references = sorted({f.reference for f in findings if f.reference})
    reference = "; ".join(references) if references else ""

    # Merge metadata
    merged_meta = {}
    for f in findings:
        merged_meta.update(f.metadata)
    merged_meta["sources"] = sources
    merged_meta["duplicate_count"] = len(findings)

    return Finding(
        title=best.title,
        severity=best.severity,
        category=best.category,
        source=", ".join(sources),
        description=best.description,
        location=best.location,
        evidence=evidence,
        remediation=remediation,
        reference=reference,
        metadata=merged_meta,
    )


def deduplicate(findings: list[Finding]) -> list[Finding]:
    """Deduplicate a list of findings from multiple modules.

    Groups findings by (title, severity, location), merges duplicates,
    and returns a deduplicated list sorted by severity (most severe first).
    """
    groups: dict[tuple, list[Finding]] = {}
    for f in findings:
        key = _dedup_key(f)
        groups.setdefault(key, []).append(f)

    deduped = [_pick_best(group) for group in groups.values()]

    # Sort: severity descending, then title ascending
    deduped.sort(key=lambda f: (-Severity.rank(f.severity), f.title.lower()))
    return deduped
