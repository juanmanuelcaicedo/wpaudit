"""Interfaz de línea de comandos de wpaudit.

Solo para sitios PROPIOS o con autorización escrita.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import sys
from pathlib import Path
from urllib.parse import urlparse

from . import __version__
from .models import SEV_RANK, SEVERITIES

C = {"g": "\033[92m", "y": "\033[93m", "x": "\033[0m"}
EXIT_ERROR = 2
EXIT_FINDINGS = 3


def log(msg: str) -> None:
    color = C["g"] if msg.startswith("[+]") else C["y"] if msg.startswith("[!]") else ""
    print(f"{color}{msg}{C['x'] if color else ''}", file=sys.stderr, flush=True)


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="wpaudit",
        description="Auditoría NO intrusiva de un sitio WordPress con informes ejecutivo y técnico.",
        epilog="Ejemplo: wpaudit https://misitio.com --authorized --client 'Mi Empresa' --auditor 'Ana Pérez'",
    )
    p.add_argument("url", help="URL del sitio (p. ej. https://misitio.com o https://misitio.com/blog)")
    p.add_argument("--authorized", action="store_true",
                   help="Confirmo que soy propietario del sitio o tengo autorización escrita para auditarlo")
    p.add_argument("--yes", action="store_true", help=argparse.SUPPRESS)  # compatibilidad con la v1.0
    p.add_argument("--client", default="", help="Cliente u organización que aparece en los informes")
    p.add_argument("--auditor", default="", help="Auditor que aparece en los informes")
    p.add_argument("--profile", choices=["quick", "standard", "full"], default="standard",
                   help="quick: motor nativo · standard: + whatweb, sslscan, wpscan · full: + nmap, nikto")
    p.add_argument("--tools", help="Herramientas externas separadas por comas (reemplaza las del perfil)")
    p.add_argument("--wpscan-token", help="Token de WPScan; mejor use la variable WPSCAN_API_TOKEN")
    p.add_argument("-o", "--output", default="reports", help="Directorio de salida (por defecto: ./reports)")
    p.add_argument("--compare", metavar="RESULTADOS_JSON", help="resultados.json de una auditoría anterior para comparar")
    p.add_argument("--fail-on", choices=SEVERITIES, help="Termina con código 3 si hay hallazgos de esta severidad o mayor")
    p.add_argument("--no-pdf", action="store_true", help="No generar PDF")
    p.add_argument("--crawl", type=int, default=6, help="Páginas internas a rastrear (por defecto: 6)")
    p.add_argument("--delay", type=float, default=0.25, help="Segundos entre peticiones (por defecto: 0.25)")
    p.add_argument("--timeout", type=int, default=15, help="Tiempo máximo por petición en segundos (por defecto: 15)")
    p.add_argument("--insecure", action="store_true", help="No verificar el certificado TLS (se reporta igualmente)")
    p.add_argument("-V", "--version", action="version", version=f"wpaudit {__version__}")
    return p.parse_args(argv)


def normalize_url(raw: str) -> str:
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    p = urlparse(raw)
    if not p.hostname:
        raise SystemExit("URL no válida.")
    return f"{p.scheme.lower()}://{p.netloc}{p.path.rstrip('/')}"


def confirm_authorization(args: argparse.Namespace, url: str) -> None:
    if args.authorized:
        return
    if not sys.stdin.isatty():
        raise SystemExit("Se requiere --authorized para ejecutar sin terminal interactiva.")
    print(f"\n{C['y']}AVISO LEGAL{C['x']}: auditar sistemas sin autorización es ilegal.\nObjetivo: {url}")
    answer = input("¿Es su propio sitio o tiene autorización escrita? Escriba 'SI' para continuar: ").strip().upper()
    if answer not in ("SI", "SÍ"):
        raise SystemExit("Auditoría cancelada.")


def compare_results(result, path: str) -> dict:
    """Compara por identificador estable de hallazgo con un resultados.json anterior."""
    previous = json.loads(Path(path).read_text(encoding="utf-8"))
    before = {f["id"]: f["title"] for f in previous.get("findings", [])}
    now = {f.id: f.title for f in result.findings}
    return {
        "previous_date": previous.get("started", ""),
        "previous_grade": previous.get("grade", "?"),
        "previous_index": previous.get("risk_index", "?"),
        "new": [title for fid, title in now.items() if fid not in before],
        "resolved": [title for fid, title in before.items() if fid not in now],
        "persisting": len(now.keys() & before.keys()),
    }


def main(argv=None) -> int:
    args = parse_args(argv)
    url = normalize_url(args.url)
    confirm_authorization(args, url)

    try:
        import jinja2  # noqa: F401
        import requests  # noqa: F401
    except ImportError as exc:
        raise SystemExit(f"Falta la dependencia {exc.name}. En Kali: sudo apt install -y python3-requests python3-jinja2")

    from .checks import Client, Ctx, run_builtin
    from .external import PROFILES, run_external
    from .models import AuditResult
    from .report import write_reports

    p = urlparse(url)
    started = dt.datetime.now().replace(microsecond=0)
    result = AuditResult(target=url, host=p.hostname or "", started=started.isoformat(),
                         client=args.client, auditor=args.auditor, profile=args.profile)
    out_dir = Path(args.output) / f"{p.hostname}_{started.strftime('%Y%m%d-%H%M')}"

    log(f"[+] wpaudit {__version__} · objetivo: {url}")
    client = Client(url, result, timeout=args.timeout, delay=args.delay, insecure=args.insecure)
    ctx = Ctx(client, result, crawl=args.crawl)
    try:
        run_builtin(ctx, log)
    except RuntimeError as exc:
        log(f"[!] {exc}")
        return EXIT_ERROR
    except KeyboardInterrupt:
        log("[!] Interrumpido; se generará un informe parcial.")
        result.cover("Ejecución", "parcial", "La auditoría fue interrumpida antes de terminar.")

    tools = [t.strip() for t in args.tools.split(",") if t.strip()] if args.tools else PROFILES[args.profile]
    if tools:
        try:
            run_external(result, client.base + client.root, tools, out_dir, args.wpscan_token, args.timeout, log)
        except KeyboardInterrupt:
            log("[!] Herramientas externas interrumpidas.")
            result.cover("Herramientas externas", "parcial", "Fueron interrumpidas antes de terminar.")
    for run in result.tool_runs:
        if run["status"] != "ok":
            result.cover(f"Herramienta {run['tool']}", "no evaluada", run["status"])
    if "Vulnerabilidades conocidas (CVE)" not in result.coverage:
        result.cover("Vulnerabilidades conocidas (CVE)", "no evaluada",
                     "Requiere WPScan con token: los plugins pueden tener fallos publicados que este informe no muestra.")
    if args.compare:
        try:
            result.meta["comparison"] = compare_results(result, args.compare)
        except (OSError, ValueError) as exc:
            log(f"[!] No se pudo leer la auditoría anterior: {exc}")

    result.finished = dt.datetime.now().replace(microsecond=0).isoformat()
    log("[+] Generando informes…")
    out_dir.mkdir(parents=True, exist_ok=True)
    out_dir.chmod(0o700)  # los informes describen debilidades del sitio
    outputs = write_reports(result, out_dir, want_pdf=not args.no_pdf)

    counts = result.counts()
    grade, label, _ = result.grade()
    print(f"\n{'=' * 60}\n Calificación: {grade}  |  Riesgo {label}  |  Índice {result.risk_index()}/100")
    print(f" Críticos: {counts['critical']}  Altos: {counts['high']}  Medios: {counts['medium']}  Bajos: {counts['low']}  Info: {counts['info']}")
    print("=" * 60)
    gaps = result.gaps()
    if gaps:
        print("\nEvaluación parcial; no se comprobó por completo:")
        for area, gap in gaps.items():
            print(f"  - {area}: {gap['detail'] or gap['status']}")
    if result.notes:
        print("\nNotas de la ejecución:")
        for note in result.notes:
            print(f"  - {note}")
    comparison = result.meta.get("comparison")
    if comparison:
        print(f"\nDesde la auditoría anterior: {len(comparison['resolved'])} corregidos, "
              f"{len(comparison['new'])} nuevos, {comparison['persisting']} sin corregir.")
    print()
    for name, path in outputs.items():
        print(f"{C['y']}[i] {path}{C['x']}" if name == "_pdf_note" else f"  → {path}")

    if args.fail_on and any(SEV_RANK[f.severity] <= SEV_RANK[args.fail_on] for f in result.findings):
        return EXIT_FINDINGS
    return 0
