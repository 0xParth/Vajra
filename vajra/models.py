"""Data models for drift detection results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    WARNING = "WARNING"
    INFO = "INFO"
    OK = "OK"


class DriftType(str, Enum):
    MATCH = "match"
    CONTENT_MISMATCH = "content_mismatch"
    PYPI_ONLY = "pypi_only"
    GITHUB_ONLY = "github_only"
    NO_GITHUB_TAG = "no_github_tag"


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    WARN = "WARN"
    CRITICAL = "CRITICAL"


@dataclass
class FileDrift:
    path: str
    drift_type: DriftType
    severity: Severity
    pypi_sha256: str | None = None
    github_sha256: str | None = None
    detail: str = ""


@dataclass
class AuditResult:
    package: str
    version: str
    verdict: Verdict
    github_repo: str = ""
    github_tag: str = ""
    github_tag_exists: bool = True
    files: list[FileDrift] = field(default_factory=list)
    pypi_file_count: int = 0
    github_file_count: int = 0

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.files if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.files if f.severity == Severity.WARNING)

    @property
    def ok_count(self) -> int:
        return sum(1 for f in self.files if f.severity == Severity.OK)

    @property
    def overlap_match_ratio(self) -> float:
        """Fraction of common files (present in both trees) that match."""
        common = [
            f for f in self.files
            if f.drift_type in (DriftType.MATCH, DriftType.CONTENT_MISMATCH)
        ]
        if not common:
            return 0.0
        matched = sum(1 for f in common if f.drift_type == DriftType.MATCH)
        return matched / len(common)

    @property
    def has_mass_drift(self) -> bool:
        return any(f.detail.startswith("[mass-drift]") for f in self.files)


@dataclass
class MaintainerInfo:
    version: str
    author: str = ""
    author_email: str = ""
    maintainer: str = ""
    maintainer_email: str = ""


@dataclass
class VersionScanResult:
    package: str
    versions_scanned: list[str] = field(default_factory=list)
    audits: list[AuditResult] = field(default_factory=list)
    maintainer_history: list[MaintainerInfo] = field(default_factory=list)
    maintainer_changed: bool = False
    file_count_anomalies: list[str] = field(default_factory=list)


class AIVerdict(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    ERROR = "error"


@dataclass
class TriageVerdict:
    file_path: str
    ai_verdict: AIVerdict
    confidence: int  # 0-100
    threat_category: str  # credential_theft, backdoor, data_exfil, benign_build, ...
    explanation: str


@dataclass
class AuditResultWithTriage(AuditResult):
    triage_verdicts: list[TriageVerdict] = field(default_factory=list)

    @property
    def confirmed_threats(self) -> int:
        return sum(1 for t in self.triage_verdicts if t.ai_verdict == AIVerdict.MALICIOUS)

    @property
    def suspicious_count(self) -> int:
        return sum(1 for t in self.triage_verdicts if t.ai_verdict == AIVerdict.SUSPICIOUS)


@dataclass
class WatchResult:
    timestamp: str
    packages_scanned: int = 0
    drift_found: int = 0
    threats_confirmed: int = 0
    audits: list[AuditResult] = field(default_factory=list)
