"""Umumiy ma'lumot modeli.

Har bir skaner (Trivy, Gitleaks, Semgrep) o'z formatida natija beradi.
Bu yerda ularning hammasini bitta `Finding` ko'rinishiga keltiramiz —
shunda hisobot ham, filtrlash ham bitta tildan boradi.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import IntEnum


class Severity(IntEnum):
    """Xavf darajasi. Tartiblash uchun son qiymatga ega (katta = xavfliroq)."""

    UNKNOWN = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @classmethod
    def parse(cls, value) -> "Severity":
        """Skanerlarning har xil yozuvini bitta darajaga keltiradi."""
        if value is None:
            return cls.UNKNOWN
        key = str(value).strip().upper()
        aliases = {
            "ERROR": cls.HIGH,        # Semgrep
            "WARNING": cls.MEDIUM,    # Semgrep
            "WARN": cls.MEDIUM,       # Dockle
            "FATAL": cls.CRITICAL,    # Dockle
            "STYLE": cls.LOW,         # Hadolint
            "INFORMATIONAL": cls.INFO,
            "MODERATE": cls.MEDIUM,
            "NEGLIGIBLE": cls.LOW,
            "NONE": cls.INFO,
        }
        if key in cls.__members__:
            return cls[key]
        return aliases.get(key, cls.UNKNOWN)

    @property
    def label(self) -> str:
        return self.name


# Hisobot/konsolda ishlatiladigan barqaror tartib (xavflidan kamga).
SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
]

# Tekshiruv toifalari -> o'zbekcha nom (hisobotda ko'rsatish uchun).
CATEGORY_LABELS = {
    "sca": "Bog'liqlik / CVE",
    "secret": "Maxfiy kalit",
    "sast": "Kod zaifligi",
    "misconfig": "Xato sozlama",
    "dast": "DAST (web)",
}


@dataclass
class Finding:
    """Bitta topilgan kamchilik."""

    scanner: str                 # trivy | gitleaks | semgrep
    category: str                # sca | secret | sast | misconfig
    severity: Severity
    title: str
    identifier: str = ""         # CVE-2023-1234, rule id, va h.k.
    description: str = ""
    file: str = ""
    start_line: int = 0
    end_line: int = 0
    remediation: str = ""        # qanday tuzatish
    reference: str = ""          # batafsil ma'lumot havolasi

    @property
    def location(self) -> str:
        if not self.file:
            return ""
        if self.start_line:
            return f"{self.file}:{self.start_line}"
        return self.file

    @property
    def category_label(self) -> str:
        return CATEGORY_LABELS.get(self.category, self.category)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.label
        d["location"] = self.location
        return d


@dataclass
class ScanResult:
    """Bitta skanerning ishlash natijasi (muvaffaqiyat yoki xato)."""

    scanner: str
    ok: bool
    error: str = ""
    findings: list = field(default_factory=list)
    duration: float = 0.0
    skipped: bool = False
    skip_reason: str = ""
