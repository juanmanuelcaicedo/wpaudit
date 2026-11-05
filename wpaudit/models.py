"""Modelos de datos compartidos por wpaudit."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 25, "high": 10, "medium": 4, "low": 1, "info": 0}
SEV_ES = {
    "critical": "Crítica",
    "high": "Alta",
    "medium": "Media",
    "low": "Baja",
    "info": "Informativa",
}
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

GRADES = [
    # (índice máximo, nota, etiqueta de riesgo, descripción)
    (3, "A", "Bajo", "Postura de seguridad sólida; solo mejoras menores."),
    (10, "B", "Bajo", "Buena postura general con algunas debilidades corregibles."),
    (24, "C", "Moderado", "Existen debilidades relevantes que conviene corregir pronto."),
    (49, "D", "Alto", "Debilidades importantes que podrían ser aprovechadas por atacantes."),
    (100, "F", "Crítico", "Exposición grave; se requiere acción inmediata."),
]


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    category: str
    description: str
    recommendation: str
    business_impact: str = ""
    evidence: list = field(default_factory=list)
    references: list = field(default_factory=list)
    affected: str = ""
    effort: str = "Medio"  # Bajo / Medio / Alto
    fix: str = ""  # fragmento de configuración o código sugerido
    source: str = "wpaudit"
    code: str = ""  # se asigna al generar el informe (WPA-001...)

    def merge(self, other: "Finding") -> None:
        """Fusiona evidencias de un hallazgo duplicado (mismo id)."""
        for ev in other.evidence:
            if ev not in self.evidence:
                self.evidence.append(ev)
        if SEV_RANK[other.severity] < SEV_RANK[self.severity]:
            self.severity = other.severity
        if other.source not in self.source:
            self.source += f", {other.source}"


@dataclass
class AuditResult:
    target: str
    host: str
    started: str
    finished: str = ""
    client: str = ""
    auditor: str = ""
    profile: str = "standard"
    findings: list = field(default_factory=list)
    positives: list = field(default_factory=list)
    meta: dict = field(default_factory=dict)
    tool_runs: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    requests_made: int = 0
    coverage: dict = field(default_factory=dict)

    # ---- gestión de hallazgos -------------------------------------------------
    def add(self, finding: Finding) -> None:
        for existing in self.findings:
            if existing.id == finding.id:
                existing.merge(finding)
                return
        self.findings.append(finding)

    def positive(self, text: str) -> None:
        if text not in self.positives:
            self.positives.append(text)

    def note(self, text: str) -> None:
        if text not in self.notes:
            self.notes.append(text)

    def sorted_findings(self) -> list:
        return sorted(self.findings, key=lambda f: (SEV_RANK[f.severity], f.category, f.id))

    def cover(self, area: str, status: str, detail: str = "") -> None:
        """Registra qué se pudo evaluar. status: 'completa', 'parcial' o 'no evaluada'."""
        self.coverage[area] = {"status": status, "detail": detail}

    def gaps(self) -> dict:
        return {a: c for a, c in self.coverage.items() if c["status"] != "completa"}

    # ---- métricas -------------------------------------------------------------
    def counts(self) -> dict:
        c = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            c[f.severity] += 1
        return c

    def risk_index(self) -> int:
        """Suma de pesos con un piso: un hallazgo grave nunca queda oculto por una nota aceptable."""
        index = min(100, sum(SEV_WEIGHT[f.severity] for f in self.findings))
        counts = self.counts()
        if counts["critical"]:
            return max(index, 50)  # al menos nota F
        if counts["high"]:
            return max(index, 25)  # al menos nota D
        return index

    def grade(self) -> tuple:
        idx = self.risk_index()
        for limit, letter, label, desc in GRADES:
            if idx <= limit:
                return letter, label, desc
        return GRADES[-1][1:]
