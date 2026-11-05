"""Integración con herramientas estándar de Kali Linux (wpscan, nmap, nikto, whatweb, sslscan).

Cada herramienta es opcional: si no está instalada se omite y queda registrado en el informe.
Se ejecutan con perfiles conservadores; no se incluyen ataques de fuerza bruta ni explotación.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import socket
import subprocess
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.parse import urlparse

from .models import AuditResult, Finding

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")

PROFILES = {
    "quick": [],
    "standard": ["whatweb", "sslscan", "wpscan"],
    "full": ["whatweb", "sslscan", "wpscan", "nmap", "nikto"],
}

RISKY_PORTS = {
    21: ("FTP", "medium", "FTP transmite credenciales en claro; use SFTP/FTPS."),
    23: ("Telnet", "high", "Telnet no cifra nada; deshabilítelo y use SSH."),
    25: ("SMTP", "info", "Verifique que no sea un relay abierto."),
    110: ("POP3", "low", "Use POP3S o IMAPS."),
    135: ("MS-RPC", "high", "No debe exponerse a Internet."),
    139: ("NetBIOS", "high", "No debe exponerse a Internet."),
    445: ("SMB", "high", "No debe exponerse a Internet."),
    1433: ("MSSQL", "high", "Bases de datos nunca deben estar expuestas públicamente."),
    2375: ("Docker API", "critical", "API de Docker sin TLS equivale a acceso root al host."),
    3306: ("MySQL/MariaDB", "high", "La base de datos no debe ser accesible desde Internet; limite a localhost/VPN."),
    3389: ("RDP", "high", "Proteja con VPN/NLA; es un objetivo habitual de ransomware."),
    5432: ("PostgreSQL", "high", "La base de datos no debe ser accesible desde Internet."),
    5900: ("VNC", "high", "Acceso remoto sin cifrado robusto; use VPN."),
    6379: ("Redis", "critical", "Redis sin autenticación permite ejecución remota; cierre el puerto."),
    9200: ("Elasticsearch", "high", "No exponga Elasticsearch a Internet."),
    11211: ("Memcached", "high", "Expuesto permite fuga de datos y amplificación DDoS."),
    27017: ("MongoDB", "high", "No exponga MongoDB a Internet."),
}


TOKEN_ARG = re.compile(r"(--api-token[ =])\S+")


def redact(text: str) -> str:
    """Oculta el token de WPScan: nunca debe llegar a informes, JSON ni archivos crudos."""
    return TOKEN_ARG.sub(r"\1***", text or "")


def _log_run(result: AuditResult, name: str, status: str, cmd: str = "", seconds: float = 0.0, note: str = "") -> None:
    result.tool_runs.append({"tool": name, "status": status, "command": redact(cmd),
                             "seconds": round(seconds, 1), "note": redact(note)})


def _run(cmd: list, timeout: int, env: dict | None = None):
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
        return p.returncode, ANSI.sub("", p.stdout), ANSI.sub("", p.stderr), time.time() - t0
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout.decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else exc.stdout) or ""
        return 124, ANSI.sub("", out), "timeout", time.time() - t0


def _save(raw_dir: Path, name: str, content: str) -> None:
    raw_dir.mkdir(parents=True, exist_ok=True)
    (raw_dir / name).write_text(redact(content), encoding="utf-8", errors="replace")


# ----------------------------------------------------------------------------
def run_whatweb(url: str, result: AuditResult, raw: Path, timeout: int) -> None:
    exe = shutil.which("whatweb")
    if not exe:
        return _log_run(result, "whatweb", "no instalado", note="sudo apt install whatweb")
    out_file = raw / "whatweb.json"
    raw.mkdir(parents=True, exist_ok=True)
    cmd = [exe, "-a", "1", "--color=never", f"--log-json={out_file}", url]
    rc, out, err, secs = _run(cmd, timeout)
    _save(raw, "whatweb.txt", out + err)
    techs = {}
    try:
        data = json.loads(out_file.read_text() or "[]")
        for entry in data if isinstance(data, list) else [data]:
            for name, info in (entry.get("plugins") or {}).items():
                ver = ",".join(map(str, info.get("version", []))) if isinstance(info, dict) else ""
                techs[name] = ver
    except (OSError, ValueError, AttributeError):
        pass
    result.meta["whatweb"] = techs
    _log_run(result, "whatweb", "ok" if rc == 0 else f"rc={rc}", " ".join(cmd), secs, f"{len(techs)} tecnologías")


def run_sslscan(host: str, port: int, result: AuditResult, raw: Path, timeout: int) -> None:
    exe = shutil.which("sslscan")
    if not exe:
        return _log_run(result, "sslscan", "no instalado", note="sudo apt install sslscan")
    cmd = [exe, "--no-colour", f"{host}:{port}"]
    rc, out, err, secs = _run(cmd, timeout)
    _save(raw, "sslscan.txt", out + err)
    enabled = re.findall(r"^\s*(SSLv2|SSLv3|TLSv1\.0|TLSv1\.1|TLSv1\.2|TLSv1\.3)\s+(enabled|disabled)", out, re.M)
    protos = {p: s for p, s in enabled}
    result.meta.setdefault("tls", {})["sslscan"] = protos
    bad = [p for p in ("SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1") if protos.get(p) == "enabled"]
    if bad:
        result.add(Finding(
            id="TLS-LEGACY", title="El servidor acepta protocolos TLS obsoletos",
            severity="high" if any(p.startswith("SSL") for p in bad) else "medium", category="Transporte",
            description="Se detectaron protocolos criptográficos obsoletos habilitados.",
            business_impact="Facilita ataques de degradación y no cumple PCI-DSS ni buenas prácticas actuales.",
            recommendation="Deshabilite SSLv2/SSLv3/TLS 1.0/TLS 1.1; permita solo TLS 1.2 y 1.3.",
            fix="# Nginx\nssl_protocols TLSv1.2 TLSv1.3;\n\n# Apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3",
            effort="Bajo", source="sslscan", evidence=[f"{p}: habilitado" for p in bad]))
    weak = re.findall(r"^\s*Accepted\s+\S+\s+\d+\s+bits\s+(\S*(?:RC4|3DES|DES-CBC|NULL|EXPORT|MD5)\S*)", out, re.M)
    if weak:
        result.add(Finding(
            id="TLS-WEAKCIPHER", title="Cifrados débiles aceptados", severity="medium", category="Transporte",
            description="El servidor acepta suites de cifrado consideradas débiles.",
            recommendation="Use una configuración TLS moderna (perfil 'Intermediate' de Mozilla SSL Configuration Generator).",
            references=["https://ssl-config.mozilla.org/"], effort="Bajo", source="sslscan",
            evidence=sorted(set(weak))[:10]))
    if re.search(r"Heartbleed.*\bvulnerable", out, re.I):
        result.add(Finding(
            id="TLS-HEARTBLEED", title="Vulnerable a Heartbleed (CVE-2014-0160)", severity="critical", category="Transporte",
            description="La implementación OpenSSL del servidor es vulnerable y puede filtrar memoria.",
            business_impact="Fuga de claves privadas, sesiones y credenciales.",
            recommendation="Actualice OpenSSL, regenere certificados/claves y revoque los anteriores.",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2014-0160"], effort="Medio", source="sslscan"))
    _log_run(result, "sslscan", "ok" if rc == 0 else f"rc={rc}", " ".join(cmd), secs)


_SEVERITY_ES = {"critical": "Crítica", "high": "Alta", "medium": "Media", "low": "Baja", "info": "Informativa"}
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_ANON = re.compile(r"unauth|authentication bypass|auth bypass", re.I)
_ADMIN_ONLY = re.compile(r"\b(super )?admin(istrator)?\+|\(admin(istrator)?\+?\)|super admin", re.I)
_TAKEOVER = re.compile(r"\brce\b|remote code|code execution|account takeover|authentication bypass|auth bypass|arbitrary file upload", re.I)
_DATA = re.compile(r"sql injection|sqli|\blfi\b|file inclusion|traversal|database access|sensitive information|file overwrite", re.I)


def estimate_severity(vuln: dict) -> str:
    """Usa el CVSS si existe; si no, estima la gravedad por lo que dice el título."""
    try:
        score = float((vuln.get("cvss") or {}).get("score"))
    except (TypeError, ValueError):
        score = None
    if score is not None:
        return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"
    title = str(vuln.get("title", ""))
    if _ADMIN_ONLY.search(title):
        return "low"
    if _ANON.search(title):
        if _TAKEOVER.search(title):
            return "critical"
        return "high" if _DATA.search(title) else "medium"
    return "high" if _TAKEOVER.search(title) else "medium"


def vulnerability_finding(label: str, vulns: list, version_known: bool = True) -> Finding | None:
    """Agrupa en un solo hallazgo las vulnerabilidades conocidas de un componente."""
    if not vulns:
        return None
    rated = sorted(((estimate_severity(v), v) for v in vulns), key=lambda item: _SEVERITY_ORDER.index(item[0]))
    severity = rated[0][0] if version_known else "low"
    evidence, references = [], []
    for sev, v in rated:
        fixed = v.get("fixed_in") or "sin parche conocido"
        evidence.append(f"[{_SEVERITY_ES[sev]}] {v.get('title', 'Vulnerabilidad conocida')} (corregida en: {fixed})")
        refs = v.get("references") or {}
        for cve in refs.get("cve", []):
            references.append(f"https://nvd.nist.gov/vuln/detail/{cve if str(cve).startswith('CVE') else 'CVE-' + str(cve)}")
        references.extend(refs.get("url", [])[:1])
    references = list(dict.fromkeys(references))[:6]
    shown = evidence[:30]
    if len(evidence) > 30:
        shown.append(f"... y {len(evidence) - 30} más en raw/wpscan.json")
    fixes = [v["fixed_in"] for v in vulns if v.get("fixed_in")]
    target = max(fixes, key=lambda x: tuple(int(i) for i in re.findall(r"\d+", str(x))[:4])) if fixes else None
    amount = f"{len(vulns)} {'vulnerabilidad conocida' if len(vulns) == 1 else 'vulnerabilidades conocidas'}"
    description = (f"WPScan reporta {amount} en {label}. Cuando la base de datos no trae CVSS, "
                   "la gravedad se estima por el título; confírmela antes de priorizar.")
    if not version_known:
        description += " No se pudo confirmar la versión instalada: algunas pueden no aplicar, por lo que este hallazgo queda en gravedad baja hasta verificarla."
    return Finding(
        id=f"VULN-{label.split(' ')[0]}-{label.split(' ')[1] if ' ' in label and label.split(' ')[0] != 'WordPress' else 'core'}"[:90],
        title=f"{label}: {amount}{' por confirmar' if not version_known else ''}",
        severity=severity, category="Vulnerabilidades conocidas", description=description,
        business_impact="Hay fallos públicos que pueden facilitar el compromiso del sitio; algunos pueden tener exploit disponible.",
        recommendation=("Actualice WordPress a la última versión estable." if label.startswith("WordPress") else
                        (f"Actualice a la versión {target} o superior" if target else "Actualice a la última versión")
                        + " o elimine el componente si no es imprescindible."),
        references=references, effort="Medio", source="wpscan", evidence=shown)


def merge_wpscan_plugins(result: AuditResult, data: dict) -> None:
    """Agrega al inventario los plugins que solo encontró WPScan."""
    plugins = result.meta.setdefault("plugins", [])
    known = {p["slug"] for p in plugins}
    for slug, info in (data.get("plugins") or {}).items():
        if slug not in known:
            plugins.append({"slug": slug, "version": (info.get("version") or {}).get("number"), "latest": None,
                            "status": "Detectado por WPScan", "last_updated": None, "installs": None})


def run_wpscan(url: str, token: str | None, result: AuditResult, raw: Path, timeout: int, light: bool = False) -> None:
    exe = shutil.which("wpscan")
    if not exe:
        return _log_run(result, "wpscan", "no instalado", note="sudo apt install wpscan")
    out_file = raw / "wpscan.json"
    raw.mkdir(parents=True, exist_ok=True)
    out_file.unlink(missing_ok=True)
    # Modo "light": detección pasiva y sin copias/volcados; se usa como reintento si el análisis completo agota el tiempo
    cmd = [exe, "--url", url, "--format", "json", "--output", str(out_file), "--no-banner",
           "--random-user-agent", "--plugins-detection", "passive" if light else "mixed",
           "--max-threads", "5", "--request-timeout", "20", "--connect-timeout", "10"]
    if token:
        cmd += ["--enumerate", "vp,vt" if light else "vp,vt,cb,dbe,u", "--api-token", token]
    else:
        # Sin token WPScan se niega a enumerar plugins/temas vulnerables (vp,vt): se piden solo
        # plugins/temas populares, copias de config, volcados de BD y usuarios, que no requieren API.
        cmd += ["--enumerate", "p,t" if light else "p,t,cb,dbe,u"]
    # WPScan también lee esta variable: el token solo se le pasa de forma explícita
    env = {k: v for k, v in os.environ.items() if k != "WPSCAN_API_TOKEN"}
    rc, out, err, secs = _run(cmd, timeout, env)
    _save(raw, "wpscan.stderr.txt", out + err)
    try:
        data = json.loads(out_file.read_text())
    except (OSError, ValueError):
        if rc == 124 and not light:
            result.note("WPScan superó el tiempo máximo en el análisis completo (hosting con límites de tasa o respuestas lentas). "
                        "Se reintentó con detección pasiva de plugins/temas (modo ligero).")
            _log_run(result, "wpscan", "tiempo agotado (análisis completo)", " ".join(cmd), secs,
                     "reintentando en modo ligero")
            return run_wpscan(url, token, result, raw, min(timeout, 300), light=True)
        if rc == 124:
            result.note("WPScan agotó el tiempo también en modo ligero y no aportó resultados. Ejecútelo aparte, por ejemplo: "
                        "wpscan --url " + url + " --enumerate vp,vt --plugins-detection passive --api-token TOKEN")
        return _log_run(result, "wpscan", "tiempo agotado" if rc == 124 else f"sin resultados (rc={rc})",
                        " ".join(cmd), secs, "timeout" if rc == 124 else (err or out)[:200])

    aborted = data.get("scan_aborted")
    if aborted and token and re.search(r"401|unauthori[sz]ed|invalid.*token|token.*invalid", str(aborted), re.I):
        # La API rechazó el token (inválido, vencido o de ejemplo): reintentar sin token en lugar de perder el análisis
        result.note("WPScan rechazó el token de API (HTTP 401): es inválido, está vencido o es un valor de ejemplo. "
                    "Se repitió el análisis sin token, por lo que NO se consultó la base de vulnerabilidades de plugins/temas. "
                    "Copie su token real desde https://wpscan.com/profile y defina la variable WPSCAN_API_TOKEN.")
        return run_wpscan(url, None, result, raw, timeout, light=light)
    if aborted:
        result.note(f"WPScan abortó el análisis y no aportó resultados: {aborted}")
        return _log_run(result, "wpscan", f"abortado (rc={rc})", " ".join(cmd), secs, str(aborted)[:200])

    vulns_total = 0
    vulns_skipped = 0

    def _own_version(kind: str, slug: str):
        """Versión detectada por el motor nativo de wpaudit (sin el sufijo '(estimada)')."""
        for it in result.meta.get(kind, []) or []:
            if it.get("slug") == slug and it.get("version"):
                return str(it["version"]).split(" ")[0]
        return None

    def _vt(x):
        parts = re.findall(r"\d+", str(x or ""))
        return tuple(int(i) for i in parts[:4]) if parts else None

    def add_vulns(label: str, vulns: list, installed=None) -> None:
        nonlocal vulns_total, vulns_skipped
        inst = _vt(installed)
        pending = []
        for v in vulns or []:
            fixed = _vt(v.get("fixed_in"))
            if inst and fixed and inst >= fixed:
                vulns_skipped += 1  # ya corregida en la versión detectada
                continue
            pending.append(v)
        vulns_total += len(pending)
        finding = vulnerability_finding(label, pending, version_known=inst is not None)
        if finding:
            result.add(finding)

    merge_wpscan_plugins(result, data)
    ver = data.get("version") or {}
    if ver:
        add_vulns(f"WordPress {ver.get('number', '')}", ver.get("vulnerabilities"), ver.get("number"))
    for slug, info in (data.get("plugins") or {}).items():
        add_vulns(f"Plugin {slug}", info.get("vulnerabilities"), (info.get("version") or {}).get("number") or _own_version("plugins", slug))
    for slug, info in (data.get("themes") or {}).items():
        add_vulns(f"Tema {slug}", info.get("vulnerabilities"), (info.get("version") or {}).get("number") or _own_version("themes", slug))
    if data.get("main_theme"):
        add_vulns(f"Tema {data['main_theme'].get('slug', '')}", data["main_theme"].get("vulnerabilities"),
                  (data["main_theme"].get("version") or {}).get("number")
                  or _own_version("themes", data["main_theme"].get("slug", "")))
    if vulns_skipped:
        result.note(f"WPScan: se descartaron {vulns_skipped} vulnerabilidades ya corregidas en la versión detectada.")

    users = list((data.get("users") or {}).keys())
    if users:
        result.meta["users"] = sorted(set(result.meta.get("users", []) + users))
    for key, label in (("config_backups", "Respaldo de configuración"), ("db_exports", "Exportación de base de datos")):
        items = list((data.get(key) or {}).keys())
        if items:
            result.add(Finding(
                id="FILE-BACKUP" if key == "db_exports" else "FILE-WPCONFIG", title=f"{label} accesible públicamente",
                severity="critical", category="Exposición de archivos",
                description=f"WPScan encontró archivos de tipo '{label}' descargables.",
                recommendation="Elimine los archivos del directorio web y rote todas las credenciales potencialmente comprometidas.",
                effort="Bajo", source="wpscan", evidence=items[:8]))
    note = f"{vulns_total} vulnerabilidades"
    if not token:
        note += "; sin API token de WPScan solo se detecta lo no dependiente de su base de vulnerabilidades (defina WPSCAN_API_TOKEN)"
        result.note("WPScan se ejecutó sin API token: las vulnerabilidades de plugins/temas pueden no aparecer. "
                    "Obtenga un token en wpscan.com y defina la variable WPSCAN_API_TOKEN.")
    _log_run(result, "wpscan", "ok" if rc in (0, 5) else f"rc={rc}", " ".join(cmd), secs, note)
    if token:
        result.cover("Vulnerabilidades conocidas (CVE)", "completa", "Consultada con WPScan y token de API.")


def run_nmap(host: str, result: AuditResult, raw: Path, timeout: int) -> None:
    exe = shutil.which("nmap")
    if not exe:
        return _log_run(result, "nmap", "no instalado", note="sudo apt install nmap")
    cmd = [exe, "-sV", "--top-ports", "1000", "-T4", "--max-retries", "2", "-Pn", "--open", "-oX", "-", host]
    rc, out, err, secs = _run(cmd, timeout)
    _save(raw, "nmap.xml", out)
    ports = []
    try:
        root = ET.fromstring(out)
        for p in root.iter("port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = p.find("service")
            ports.append({
                "port": int(p.get("portid")), "proto": p.get("protocol"),
                "service": svc.get("name") if svc is not None else "",
                "product": " ".join(filter(None, [svc.get("product"), svc.get("version")])) if svc is not None else "",
            })
    except ET.ParseError:
        if rc == 124:
            result.note("nmap superó el tiempo máximo y se canceló sin resultados; los puertos no fueron evaluados. "
                        "Ejecútelo aparte: nmap -sV --top-ports 1000 -Pn <host>")
            return _log_run(result, "nmap", "tiempo agotado", " ".join(cmd), secs, "sin resultados (timeout)")
        return _log_run(result, "nmap", f"salida no válida (rc={rc})", " ".join(cmd), secs)
    result.meta["open_ports"] = ports
    extra = [p for p in ports if p["port"] not in (80, 443)]
    if extra:
        result.note("nmap encontró puertos distintos de 80/443 (" + ", ".join(str(p["port"]) for p in extra) + "). "
                    "Si el sitio está en un hosting gestionado (WordPress.com, CDN) o su red tiene firewall/proxy "
                    "(p. ej. FortiGuard en 8010, SIP en 5060), pueden pertenecer a un equipo intermedio y no al servidor "
                    "auditado: verifíquelo ejecutando nmap desde otra red antes de reportarlos como hallazgo.")
    for p in ports:
        if p["port"] in RISKY_PORTS:
            label, sev, advice = RISKY_PORTS[p["port"]]
            result.add(Finding(
                id=f"PORT-{p['port']}", title=f"Puerto {p['port']}/{p['proto']} ({label}) accesible desde Internet",
                severity=sev, category="Servicios de red",
                description=f"El servicio {label} responde desde el exterior.", business_impact="Amplía la superficie de ataque más allá del sitio web.",
                recommendation=advice + " Cierre el puerto en el firewall si no es imprescindible.",
                fix=f"# UFW\nsudo ufw deny {p['port']}/{p['proto']}", effort="Bajo", source="nmap",
                evidence=[f"{p['port']}/{p['proto']} {p['service']} {p['product']}".strip()]))
    _log_run(result, "nmap", "ok" if rc == 0 else f"rc={rc}", " ".join(cmd), secs, f"{len(ports)} puertos abiertos")


def run_nikto(url: str, result: AuditResult, raw: Path, timeout: int) -> None:
    exe = shutil.which("nikto")
    if not exe:
        return _log_run(result, "nikto", "no instalado", note="sudo apt install nikto")
    raw.mkdir(parents=True, exist_ok=True)
    out_file = raw / "nikto.json"
    cmd = [exe, "-h", url, "-ask", "no", "-nointeractive", "-Format", "json", "-output", str(out_file),
           "-maxtime", f"{max(60, timeout - 30)}s", "-Tuning", "123b"]
    rc, out, err, secs = _run(cmd, timeout)
    _save(raw, "nikto.txt", out + err)
    msgs = []

    def noisy(test_id) -> bool:
        # IDs 999xxx son avisos informativos de Nikto (cabeceras no comunes, métodos basura, etc.);
        # 000427 y 011799 solo describen cabeceras Link/alt-svc estándar.
        tid = str(test_id)
        return tid.startswith("999") or tid in ("000427", "011799")

    try:
        data = json.loads(out_file.read_text())

        def walk(o):
            if isinstance(o, dict):
                if "msg" in o and not noisy(o.get("id", "")):
                    msgs.append(f"{o.get('url', '')} — {o['msg']}".strip(" —"))
                for v in o.values():
                    walk(v)
            elif isinstance(o, list):
                for v in o:
                    walk(v)
        walk(data)
    except (OSError, ValueError):
        # Sin JSON (p. ej. se agotó el tiempo): usar solo líneas con ID de prueba, descartando banners y avisos informativos
        for l in out.splitlines():
            m = re.match(r"^\+ \[(\d+)\]\s+(.*)", l.strip())
            if m and not noisy(m.group(1)):
                msgs.append(m.group(2))
        msgs = msgs[:40]
    if rc == 124:
        result.note("Nikto superó el tiempo máximo; el análisis puede estar incompleto (revise raw/nikto.txt).")
    if msgs:
        result.add(Finding(
            id="NIKTO-OBS", title=f"Observaciones del escáner Nikto ({len(msgs)})", severity="low",
            category="Configuración del servidor",
            description="Nikto reporta posibles problemas de configuración. Pueden incluir falsos positivos y deben validarse manualmente.",
            recommendation="Revise cada observación y corrija las que apliquen (cabeceras, archivos por defecto, métodos HTTP, versiones).",
            references=["https://cirt.net/Nikto2"], effort="Medio", source="nikto", evidence=msgs[:30]))
    _log_run(result, "nikto", "ok" if rc in (0, 1) else f"rc={rc}", " ".join(cmd), secs, f"{len(msgs)} observaciones")


def run_external(result: AuditResult, base_url: str, tools: list, out_dir: Path,
                 wpscan_token: str | None, timeout: int, log) -> None:
    p = urlparse(base_url)
    host = p.hostname or ""
    port = p.port or (443 if p.scheme == "https" else 80)
    raw = out_dir / "raw"
    try:
        socket.gethostbyname(host)
    except OSError:
        result.note("No se pudo resolver el nombre de host para las herramientas externas.")
        return
    token = (wpscan_token or os.environ.get("WPSCAN_API_TOKEN") or "").strip() or None
    for tool in tools:
        if tool == "sslscan" and p.scheme != "https":
            log("[i] Herramienta externa omitida: sslscan (el sitio no usa HTTPS)")
            _log_run(result, "sslscan", "omitida", note="El sitio no usa HTTPS")
            continue
        log(f"[+] Herramienta externa: {tool}")
        try:
            if tool == "whatweb":
                run_whatweb(base_url, result, raw, timeout)
            elif tool == "sslscan" and p.scheme == "https":
                run_sslscan(host, port, result, raw, timeout)
            elif tool == "wpscan":
                run_wpscan(base_url, token, result, raw, max(timeout * 3, 600))
            elif tool == "nmap":
                run_nmap(host, result, raw, max(timeout * 3, 600))
            elif tool == "nikto":
                run_nikto(base_url, result, raw, max(timeout * 3, 420))
        except Exception as exc:  # noqa: BLE001
            _log_run(result, tool, "error", note=f"{type(exc).__name__}: {exc}")
