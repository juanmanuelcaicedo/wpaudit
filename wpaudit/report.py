"""Generación de informes: ejecutivo y técnico (HTML + PDF opcional), JSON y CSV."""
from __future__ import annotations

import csv
import dataclasses
import datetime as dt
import json
import shutil
import subprocess
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import __version__
from .models import SEV_ES, SEV_RANK, SEVERITIES, AuditResult

EFFORT_RANK = {"Bajo": 0, "Medio": 1, "Alto": 2}

GENERIC_IMPACT = {
    "critical": "Podría permitir a un atacante tomar el control del sitio o acceder a datos sensibles con muy poco esfuerzo.",
    "high": "Facilita significativamente un ataque exitoso contra el sitio o sus usuarios.",
    "medium": "Aumenta la probabilidad o el impacto de un ataque cuando se combina con otras debilidades.",
    "low": "Debilita la defensa en profundidad; por sí sola tiene impacto limitado.",
    "info": "Buena práctica o dato informativo sin riesgo directo.",
}

TEMPLATES = Path(__file__).parent / "templates"


def _dedupe_runs(runs):
    """Una sola fila por herramienta: si hubo reintento, se muestra el último intento."""
    last = {}
    for i, r in enumerate(runs):
        last[r["tool"]] = i
    return [r for i, r in enumerate(runs) if last[r["tool"]] == i]


def _is_web_url(value) -> bool:
    return str(value).lower().startswith(("https://", "http://"))


def _env() -> Environment:
    env = Environment(loader=FileSystemLoader(TEMPLATES), autoescape=select_autoescape(default=True, default_for_string=True))
    env.filters["is_web_url"] = _is_web_url
    env.tests["is_web_url"] = _is_web_url
    return env


def build_context(result: AuditResult) -> dict:
    findings = result.sorted_findings()
    for i, f in enumerate(findings, 1):
        f.code = f"WPA-{i:03d}"
    counts = result.counts()
    grade, risk_label, grade_desc = result.grade()
    total = sum(counts.values()) - counts["info"]

    if total == 0:
        summary = (f"La revisión de {result.host} no identificó debilidades de severidad crítica, alta, media o baja con las pruebas realizadas. "
                   "Se recomienda mantener las actualizaciones y repetir la auditoría periódicamente.")
    else:
        parts = [f"{counts[s]} {SEV_ES[s].lower()}{'s' if counts[s] != 1 and not SEV_ES[s].endswith('a') else ('s' if counts[s] != 1 else '')}"
                 for s in ("critical", "high", "medium", "low") if counts[s]]
        summary = (f"La revisión de seguridad de {result.host} identificó {total} {'hallazgo' if total == 1 else 'hallazgos'}: " + ", ".join(parts) + ". ")
        if counts["critical"] or counts["high"]:
            summary += ("Existen debilidades de prioridad alta o crítica que conviene corregir de inmediato, ya que podrían ser aprovechadas "
                        "por atacantes para comprometer el sitio o la información de sus usuarios. ")
        else:
            summary += "No se detectaron exposiciones críticas; las mejoras recomendadas fortalecerán la defensa del sitio. "

    def keyfn(f):
        return (SEV_RANK[f.severity], EFFORT_RANK.get(f.effort, 1))

    plan = [
        {"name": "Acciones inmediatas", "window": "0 a 7 días (riesgo crítico y alto)",
         "items": sorted([f for f in findings if f.severity in ("critical", "high")], key=keyfn)},
        {"name": "Corto plazo", "window": "hasta 30 días (riesgo medio)",
         "items": sorted([f for f in findings if f.severity == "medium"], key=keyfn)},
        {"name": "Mejora continua", "window": "hasta 90 días (riesgo bajo e informativo)",
         "items": sorted([f for f in findings if f.severity in ("low", "info")], key=keyfn)},
    ]
    meta = dict(result.meta)
    meta.setdefault("response_headers", {})
    return {
        "css": (TEMPLATES / "report.css").read_text(encoding="utf-8"), "js": (TEMPLATES / "report.js").read_text(encoding="utf-8"),
        "version": __version__, "target": result.target, "host": result.host, "client": result.client, "auditor": result.auditor,
        "date_long": dt.datetime.fromisoformat(result.started).strftime("%d/%m/%Y %H:%M"),
        "started": result.started.replace("T", " ")[:19], "finished": (result.finished or "").replace("T", " ")[:19],
        "grade": grade, "risk_label": risk_label, "grade_desc": grade_desc, "risk_index": result.risk_index(),
        "counts": counts, "severities": SEVERITIES, "sev_es": SEV_ES, "generic_impact": GENERIC_IMPACT,
        "summary": summary, "findings": findings,
        "top_risks": [f for f in findings if f.severity in ("critical", "high", "medium")][:5],
        "positives": result.positives, "plan": plan, "meta": meta, "profile": result.profile,
        "tool_runs": _dedupe_runs(result.tool_runs), "notes": [n for n in result.notes if "soft-404" in n],
        "requests_made": result.requests_made,
        "coverage": result.coverage, "gaps": list(result.gaps()), "comparison": result.meta.get("comparison"),
    }


def to_pdf(html_path: Path, pdf_path: Path) -> str | None:
    """Intenta convertir a PDF con los motores disponibles. Devuelve el motor usado o None."""
    try:
        from weasyprint import HTML  # type: ignore
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return "weasyprint"
    except Exception:  # noqa: BLE001
        pass
    exe = shutil.which("weasyprint")
    if exe and subprocess.run([exe, str(html_path), str(pdf_path)], capture_output=True).returncode == 0:
        return "weasyprint"
    exe = shutil.which("wkhtmltopdf")
    if exe and subprocess.run([exe, "--quiet", "--enable-local-file-access", str(html_path), str(pdf_path)],
                              capture_output=True).returncode in (0, 1) and pdf_path.exists():
        return "wkhtmltopdf"
    for name in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
        exe = shutil.which(name)
        if exe:
            subprocess.run([exe, "--headless", "--no-sandbox", "--disable-gpu", f"--print-to-pdf={pdf_path}",
                            "--no-pdf-header-footer", html_path.resolve().as_uri()], capture_output=True)
            if pdf_path.exists():
                return name
    return None


def write_reports(result: AuditResult, out_dir: Path, want_pdf: bool = True) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    env = _env()
    ctx = build_context(result)
    outputs = {}
    for key, fname in (("exec", "informe_ejecutivo"), ("tech", "informe_tecnico")):
        html = env.get_template(f"{key}.html").render(**ctx)
        hp = out_dir / f"{fname}.html"
        hp.write_text(html, encoding="utf-8")
        outputs[f"{fname}.html"] = hp
        if want_pdf:
            pp = out_dir / f"{fname}.pdf"
            engine = to_pdf(hp, pp)
            if engine:
                outputs[f"{fname}.pdf"] = pp
            else:
                outputs.setdefault("_pdf_note", "No hay motor PDF (instale: sudo apt install weasyprint). "
                                                "Abra el HTML en el navegador y use Imprimir → Guardar como PDF.")
    # JSON completo y CSV de hallazgos
    jp = out_dir / "resultados.json"
    data = dataclasses.asdict(result)
    data["grade"], data["risk_label"], _ = result.grade()
    data["risk_index"] = result.risk_index()
    jp.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    outputs["resultados.json"] = jp
    cp = out_dir / "hallazgos.csv"
    with cp.open("w", newline="", encoding="utf-8-sig") as fh:
        w = csv.writer(fh)
        w.writerow(["Ref", "Severidad", "Categoría", "Hallazgo", "Afectado/Evidencia", "Recomendación", "Esfuerzo", "Fuente"])
        for f in result.sorted_findings():
            w.writerow([f.code, SEV_ES[f.severity], f.category, f.title, " | ".join(f.evidence)[:500],
                        f.recommendation, f.effort, f.source])
    outputs["hallazgos.csv"] = cp
    return outputs
