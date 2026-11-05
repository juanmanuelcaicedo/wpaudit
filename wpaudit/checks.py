"""Comprobaciones nativas, NO intrusivas, para auditar un sitio WordPress propio.

Principios de diseño:
  * Solo peticiones de lectura (GET/HEAD/OPTIONS) y un POST inofensivo a xmlrpc
    (system.listMethods). No se hace fuerza bruta, ni explotación, ni inyección.
  * No se siguen redirecciones a hosts fuera del alcance.
  * Retardo configurable entre peticiones para no saturar el servidor.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import random
import re
import socket
import ssl
import string
import time
import warnings
from urllib.parse import urljoin, urlparse

import requests

from . import __version__
from .models import AuditResult, Finding

UA = f"wpaudit/{__version__} (auditoria de seguridad autorizada)"
OWASP_WSTG = "https://owasp.org/www-project-web-security-testing-guide/"
WP_HARDENING = "https://developer.wordpress.org/advanced-administration/security/hardening/"
OWASP_HEADERS = "https://owasp.org/www-project-secure-headers/"

warnings.filterwarnings("ignore", category=DeprecationWarning)
requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]


class ScopeError(Exception):
    """Una redirección intentó salir del alcance autorizado."""


class ApiUnavailable(Exception):
    """api.wordpress.org no respondió; no equivale a que el componente no exista."""


# =============================================================================
# Cliente HTTP con control de alcance
# =============================================================================
class Client:
    def __init__(self, base: str, result: AuditResult, timeout: int = 15,
                 delay: float = 0.25, insecure: bool = False):
        p = urlparse(base)
        self.scheme = p.scheme
        self.base = f"{p.scheme}://{p.netloc}"
        self.host = p.hostname or ""
        self.port = p.port or (443 if p.scheme == "https" else 80)
        self.root = p.path.rstrip("/")
        bare = self.host[4:] if self.host.startswith("www.") else self.host
        self.allowed = {bare, "www." + bare}
        self.timeout = timeout
        self.delay = delay
        self.result = result
        self.tls_problem: str | None = None
        self.limited = 0  # respuestas 429/5xx: el servidor o un WAF limitó la auditoría
        self.failed = 0  # peticiones sin respuesta
        self.s = requests.Session()
        self.s.headers.update({"User-Agent": UA, "Accept": "*/*"})
        self.s.verify = not insecure

    def url(self, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        return f"{self.base}{self.root}/{path.lstrip('/')}"

    def request(self, method: str, path: str, follow: bool = True, **kw):
        url = self.url(path)
        time.sleep(self.delay)
        r = None
        for _ in range(6):
            host = urlparse(url).hostname
            if host not in self.allowed:
                raise ScopeError(f"Redirección fuera de alcance hacia {host}")
            self.result.requests_made += 1
            try:
                r = self.s.request(method, url, timeout=self.timeout,
                                   allow_redirects=False, **kw)
            except requests.exceptions.SSLError as exc:
                if not self.s.verify:
                    raise
                self.tls_problem = str(exc)[:300]
                self.s.verify = False  # continuamos la auditoría pero lo reportamos
                continue
            if follow and r.status_code in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                url = urljoin(url, r.headers["Location"])
                continue
            if r.status_code == 429 or r.status_code >= 500:
                self.limited += 1
            return r
        return r

    def _safe(self, method: str, path: str, strict: bool, **kw):
        """Una ruta que redirige fuera del alcance no detiene la comprobación; solo se omite."""
        try:
            return self.request(method, path, **kw)
        except ScopeError:
            if strict:
                raise
            return None
        except requests.RequestException:
            self.failed += 1
            return None

    def get(self, path: str, strict: bool = False, **kw):
        return self._safe("GET", path, strict, **kw)

    def post(self, path: str, strict: bool = False, **kw):
        return self._safe("POST", path, strict, **kw)


class Ctx:
    def __init__(self, client: Client, result: AuditResult, crawl: int = 6):
        self.c = client
        self.r = result
        self.crawl = crawl
        self.home = None
        self.html = ""
        self.pages: dict[str, str] = {}
        self.is_wp = False
        self.wp_version: str | None = None
        self.soft404: tuple | None = None
        self.online_api_ok = True

    def blob(self) -> str:
        return "\n".join(self.pages.values())

    @staticmethod
    def conclusive(resp) -> bool:
        """False si no hubo respuesta o el servidor limitó la petición: no prueba que un control exista."""
        return resp is not None and resp.status_code != 429 and resp.status_code < 500

    def is_soft404(self, resp) -> bool:
        if not self.soft404 or resp is None:
            return False
        return hashlib.md5(resp.content).hexdigest() == self.soft404[1]


def vkey(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v or "")[:4]) or (0,)


def wp_api(path: str, params: dict | None = None):
    r = requests.get("https://api.wordpress.org/" + path, params=params, timeout=10,
                     headers={"User-Agent": UA})
    r.raise_for_status()
    return r.json()


# =============================================================================
# 1. Acceso inicial, rastreo ligero y calibración
# =============================================================================
def fetch_home(ctx: Ctx) -> None:
    try:
        r = ctx.c.get("/", strict=True)
    except ScopeError as exc:
        raise RuntimeError(f"{exc}. Audite la URL final del sitio; no se generó ningún informe.") from exc
    if r is None:
        raise RuntimeError("No se pudo acceder al sitio (¿URL correcta y servidor accesible?)")
    if r.status_code != 200:
        ctx.r.cover("Portada", "parcial", f"La portada respondió HTTP {r.status_code}; un bloqueo puede ocultar hallazgos.")
    ctx.home = r
    ctx.html = r.text
    ctx.pages["/"] = r.text
    ctx.r.meta["home_status"] = r.status_code
    ctx.r.meta["final_url"] = r.url
    ctx.r.meta["response_headers"] = {k: v for k, v in r.headers.items()}

    # Rastreo ligero: enlaces internos de la portada
    host_ok = ctx.c.allowed
    links = []
    for href in re.findall(r"""href=["']([^"'#]+)["']""", r.text):
        full = urljoin(r.url, href)
        pu = urlparse(full)
        if pu.hostname in host_ok and not re.search(r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|pdf|zip|xml)(\?|$)", pu.path, re.I):
            if "/wp-json" in pu.path or "xmlrpc" in pu.path or "wp-login" in pu.path:
                continue
            if full not in links:
                links.append(full)
    for link in links[: ctx.crawl]:
        pr = ctx.c.get(link)
        if pr is not None and pr.status_code == 200 and "text/html" in pr.headers.get("Content-Type", ""):
            ctx.pages[link] = pr.text


def calibrate(ctx: Ctx) -> None:
    name = "/wpaudit-" + "".join(random.choices(string.ascii_lowercase, k=12)) + ".html"
    r = ctx.c.get(name)
    if r is not None and r.status_code == 200:
        ctx.soft404 = (len(r.content), hashlib.md5(r.content).hexdigest())
        ctx.r.note("El sitio responde HTTP 200 a páginas inexistentes (soft-404); "
                   "los hallazgos de archivos se validan por contenido para evitar falsos positivos.")


def detect_is_wordpress(ctx: Ctx) -> None:
    blob = ctx.blob()
    hdrs = ctx.r.meta.get("response_headers", {})
    indicators = [
        "/wp-content/" in blob,
        "/wp-includes/" in blob,
        'name="generator" content="WordPress' in blob,
        "api.w.org" in json.dumps(hdrs),
    ]
    ctx.is_wp = any(indicators)
    ctx.r.meta["is_wordpress"] = ctx.is_wp
    if not ctx.is_wp:
        ctx.r.add(Finding(
            id="WP-NOTDETECTED", title="No se detectaron indicadores claros de WordPress",
            severity="info", category="Reconocimiento",
            description="La página principal no expone señales típicas de WordPress (wp-content, wp-includes, "
                        "meta generator). Puede estar detrás de un proxy/caché o usar otra tecnología.",
            recommendation="Verifique que la URL auditada sea la correcta. Los chequeos específicos de WordPress "
                           "pueden producir resultados incompletos.", effort="Bajo"))


# =============================================================================
# 2. Transporte: HTTPS, redirección y TLS
# =============================================================================
def check_transport(ctx: Ctx) -> None:
    c = ctx.c
    if c.scheme == "http":
        ctx.r.add(Finding(
            id="TLS-NOHTTPS", title="El sitio se sirve sin HTTPS", severity="high", category="Transporte",
            description="La URL auditada utiliza HTTP en claro. Credenciales, cookies de sesión y contenido "
                        "viajan sin cifrar y pueden ser interceptados o alterados.",
            business_impact="Un atacante en la misma red (Wi-Fi público, proveedor) podría robar sesiones de "
                            "administrador o inyectar contenido malicioso a sus visitantes.",
            recommendation="Instale un certificado TLS (p. ej. Let's Encrypt), redirija todo el tráfico HTTP a "
                           "HTTPS y actualice las URLs de WordPress (Ajustes → Generales) a https://.",
            references=[OWASP_WSTG, "https://letsencrypt.org/getting-started/"], effort="Bajo",
            evidence=[f"URL auditada: {ctx.c.base}"]))
        return
    # ¿http:// redirige a https://?
    try:
        r = requests.get(f"http://{c.host}{c.root}/", timeout=c.timeout, allow_redirects=False,
                         headers={"User-Agent": UA}, verify=False)
        ctx.r.requests_made += 1
        loc = r.headers.get("Location", "")
        if not (r.status_code in (301, 302, 307, 308) and loc.startswith("https://")):
            ctx.r.add(Finding(
                id="TLS-NOREDIRECT", title="HTTP no redirige a HTTPS", severity="medium", category="Transporte",
                description="El puerto 80 responde sin redirigir a la versión cifrada del sitio.",
                business_impact="Usuarios que escriban la URL sin https:// navegarán sin cifrado.",
                recommendation="Configure una redirección permanente 301 de http:// a https:// en el servidor web.",
                fix="# Nginx\nserver { listen 80; server_name ejemplo.com www.ejemplo.com; return 301 https://$host$request_uri; }\n\n"
                    "# Apache (.htaccess)\nRewriteEngine On\nRewriteCond %{HTTPS} off\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]",
                references=[OWASP_WSTG], effort="Bajo",
                evidence=[f"GET http://{c.host}/ → HTTP {r.status_code} Location: {loc or '(sin Location)'}"]))
        else:
            ctx.r.positive("HTTP redirige correctamente a HTTPS.")
    except requests.RequestException:
        ctx.r.note("No se pudo verificar la redirección HTTP→HTTPS (puerto 80 no accesible).")


def _handshake(host: str, port: int, cx: ssl.SSLContext):
    with socket.create_connection((host, port), timeout=10) as s:
        with cx.wrap_socket(s, server_hostname=host) as ss:
            return ss.getpeercert(), ss.version(), ss.cipher()


def _legacy_proto(host: str, port: int, ver) -> bool | None:
    try:
        cx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        cx.check_hostname = False
        cx.verify_mode = ssl.CERT_NONE
        cx.minimum_version = ver
        cx.maximum_version = ver
        cx.set_ciphers("ALL:@SECLEVEL=0")
    except (ValueError, ssl.SSLError):
        return None
    try:
        _handshake(host, port, cx)
        return True
    except ssl.SSLError as exc:
        return None if "NO_PROTOCOLS_AVAILABLE" in str(exc) else False
    except OSError:
        return False


def check_tls(ctx: Ctx) -> None:
    c = ctx.c
    if c.scheme != "https":
        return
    tls: dict = {"host": c.host, "port": c.port}
    try:
        cert, proto, cipher = _handshake(c.host, c.port, ssl.create_default_context())
        tls.update(protocol=proto, cipher=cipher[0] if cipher else "", cert_valid=True)
        not_after = ssl.cert_time_to_seconds(cert["notAfter"])
        days = int((not_after - time.time()) // 86400)
        tls["days_left"] = days
        tls["not_after"] = cert["notAfter"]
        tls["issuer"] = ", ".join("=".join(x) for rdn in cert.get("issuer", ()) for x in rdn)
        tls["subject"] = ", ".join("=".join(x) for rdn in cert.get("subject", ()) for x in rdn)
        tls["san"] = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:15]
        if days < 15:
            ctx.r.add(Finding(
                id="TLS-EXPIRING", title=f"El certificado TLS vence en {days} días",
                severity="high" if days < 7 else "medium", category="Transporte",
                description="El certificado está próximo a expirar; al vencer los navegadores bloquearán el sitio.",
                business_impact="Pérdida de acceso y confianza de los visitantes si la renovación falla.",
                recommendation="Renueve el certificado y verifique que la renovación automática (certbot/ACME) funcione.",
                effort="Bajo", evidence=[f"Válido hasta: {cert['notAfter']}"], references=[OWASP_WSTG]))
        else:
            ctx.r.positive(f"Certificado TLS válido y de confianza (vence en {days} días).")
    except ssl.SSLCertVerificationError as exc:
        tls["cert_valid"] = False
        tls["verify_error"] = exc.verify_message
        ctx.r.add(Finding(
            id="TLS-CERT", title="Certificado TLS inválido o no confiable", severity="high", category="Transporte",
            description="El certificado presentado no supera la verificación estándar.",
            business_impact="Los navegadores muestran advertencias de seguridad y los usuarios pueden ser "
                            "víctimas de ataques de intermediario sin darse cuenta.",
            recommendation="Instale un certificado emitido por una CA reconocida que cubra el dominio y la "
                           "cadena intermedia completa.", effort="Bajo", references=[OWASP_WSTG],
            evidence=[f"Error de verificación: {exc.verify_message}"]))
        try:
            cx = ssl.create_default_context()
            cx.check_hostname = False
            cx.verify_mode = ssl.CERT_NONE
            _, proto, cipher = _handshake(c.host, c.port, cx)
            tls.update(protocol=proto, cipher=cipher[0] if cipher else "")
        except (ssl.SSLError, OSError):
            pass
    except (ssl.SSLError, OSError) as exc:
        ctx.r.note(f"No se pudo completar el análisis TLS nativo: {exc}")
        ctx.r.meta["tls"] = tls
        return

    legacy = {}
    for name, ver in (("TLSv1.0", ssl.TLSVersion.TLSv1), ("TLSv1.1", ssl.TLSVersion.TLSv1_1)):
        legacy[name] = _legacy_proto(c.host, c.port, ver)
    tls["legacy"] = {k: ("aceptado" if v else "rechazado" if v is False else "no concluyente") for k, v in legacy.items()}
    accepted = [k for k, v in legacy.items() if v]
    if accepted:
        ctx.r.add(Finding(
            id="TLS-LEGACY", title="El servidor acepta protocolos TLS obsoletos", severity="medium",
            category="Transporte",
            description="TLS 1.0/1.1 están deprecados (RFC 8996) y presentan debilidades criptográficas conocidas.",
            business_impact="Facilita ataques de degradación y no cumple PCI-DSS ni buenas prácticas actuales.",
            recommendation="Deshabilite TLS 1.0 y 1.1; permita solo TLS 1.2 y 1.3.",
            fix="# Nginx\nssl_protocols TLSv1.2 TLSv1.3;\n\n# Apache\nSSLProtocol -all +TLSv1.2 +TLSv1.3",
            references=["https://datatracker.ietf.org/doc/html/rfc8996"], effort="Bajo",
            evidence=[f"Protocolo aceptado: {p}" for p in accepted]))
    elif tls.get("protocol") in ("TLSv1.3", "TLSv1.2"):
        ctx.r.positive(f"Protocolo TLS moderno negociado ({tls['protocol']}).")
    ctx.r.meta["tls"] = tls


# =============================================================================
# 3. Cabeceras HTTP, divulgación de información y cookies
# =============================================================================
PHP_EOL = {"7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31",
           "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31"}

HEADER_FIX = """# Apache (.htaccess o vhost)
<IfModule mod_headers.c>
  Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always set Referrer-Policy "strict-origin-when-cross-origin"
  Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
</IfModule>

# Nginx (bloque server)
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;"""


def check_headers(ctx: Ctx) -> None:
    h = {k.lower(): v for k, v in ctx.r.meta.get("response_headers", {}).items()}
    https = ctx.c.scheme == "https"
    table = []

    def present(name):
        return name in h

    # HSTS
    if https:
        if present("strict-transport-security"):
            m = re.search(r"max-age=(\d+)", h["strict-transport-security"])
            age = int(m.group(1)) if m else 0
            table.append(("Strict-Transport-Security", h["strict-transport-security"], "OK" if age >= 15552000 else "Débil"))
            if age < 15552000:
                ctx.r.add(Finding(
                    id="HDR-HSTS-WEAK", title="HSTS con duración insuficiente", severity="low", category="Cabeceras HTTP",
                    description="max-age de HSTS es inferior a 6 meses.", recommendation="Use max-age de al menos 31536000 (1 año).",
                    fix=HEADER_FIX, effort="Bajo", references=[OWASP_HEADERS], evidence=[f"Strict-Transport-Security: {h['strict-transport-security']}"]))
            else:
                ctx.r.positive("Cabecera HSTS configurada correctamente.")
        else:
            table.append(("Strict-Transport-Security", "—", "Ausente"))
            ctx.r.add(Finding(
                id="HDR-HSTS", title="Falta la cabecera HSTS (Strict-Transport-Security)", severity="medium",
                category="Cabeceras HTTP",
                description="Sin HSTS el navegador puede conectarse inicialmente por HTTP, permitiendo ataques de degradación (SSL stripping).",
                business_impact="Aumenta el riesgo de interceptación de sesiones en redes no confiables.",
                recommendation="Active HSTS tras confirmar que todo el sitio y subdominios funcionan correctamente por HTTPS.",
                fix=HEADER_FIX, references=[OWASP_HEADERS], effort="Bajo"))

    missing = []
    csp = h.get("content-security-policy", "")
    checks = [
        ("Content-Security-Policy", present("content-security-policy")),
        ("X-Frame-Options", present("x-frame-options") or "frame-ancestors" in csp),
        ("X-Content-Type-Options", "nosniff" in h.get("x-content-type-options", "").lower()),
        ("Referrer-Policy", present("referrer-policy")),
        ("Permissions-Policy", present("permissions-policy")),
    ]
    for name, ok in checks:
        table.append((name, h.get(name.lower(), "—") if name.lower() in h else ("(vía CSP)" if ok else "—"), "OK" if ok else "Ausente"))
        if not ok:
            missing.append(name)
    if missing:
        ctx.r.add(Finding(
            id="HDR-MISSING", title="Cabeceras de seguridad HTTP recomendadas ausentes", severity="low",
            category="Cabeceras HTTP",
            description="Las cabeceras de seguridad reducen el impacto de ataques como clickjacking, MIME sniffing, "
                        "fuga de referrer y XSS. Faltan: " + ", ".join(missing) + ".",
            business_impact="Menor defensa en profundidad frente a ataques en el navegador del visitante.",
            recommendation="Añada las cabeceras ausentes en el servidor web. Para CSP, empiece en modo "
                           "Content-Security-Policy-Report-Only y ajuste según los recursos de su tema/plugins.",
            fix=HEADER_FIX, references=[OWASP_HEADERS, "https://developer.mozilla.org/docs/Web/HTTP/CSP"],
            effort="Bajo", evidence=[f"Ausente: {m}" for m in missing]))
    else:
        ctx.r.positive("Todas las cabeceras de seguridad recomendadas están presentes.")
    ctx.r.meta["security_headers"] = table

    # --- Divulgación de información ---
    leaks = []
    server = h.get("server", "")
    if re.search(r"\d+\.\d+", server):
        leaks.append(f"Server: {server}")
    xpb = h.get("x-powered-by", "")
    if xpb:
        leaks.append(f"X-Powered-By: {xpb}")
    if leaks:
        ctx.r.add(Finding(
            id="INFO-BANNER", title="El servidor divulga versiones de software", severity="low",
            category="Divulgación de información",
            description="Las cabeceras revelan tecnología y versiones exactas, facilitando la búsqueda de vulnerabilidades específicas.",
            recommendation="Oculte versiones: ServerTokens Prod / server_tokens off / expose_php = Off.",
            fix="# Apache\nServerTokens Prod\nServerSignature Off\n\n# Nginx\nserver_tokens off;\n\n# php.ini\nexpose_php = Off",
            references=[OWASP_WSTG], effort="Bajo", evidence=leaks))
    # --- PHP fin de vida ---
    m = re.search(r"PHP/(\d+\.\d+)(?:\.\d+)?", xpb) or re.search(r"PHP/(\d+\.\d+)", server)
    if m:
        branch = m.group(1)
        ctx.r.meta["php_version"] = m.group(0).split("/")[1]
        eol = PHP_EOL.get(branch)
        today = dt.date.today()
        is_eol = (eol and dt.date.fromisoformat(eol) < today) or vkey(branch) < (7, 4)
        if is_eol:
            ctx.r.add(Finding(
                id="PHP-EOL", title=f"PHP {branch} está fuera de soporte", severity="high", category="Plataforma",
                description="Las ramas de PHP sin soporte no reciben parches de seguridad, aunque WordPress esté actualizado.",
                business_impact="Vulnerabilidades conocidas del lenguaje quedan sin corregir y pueden comprometer todo el servidor.",
                recommendation="Migre a una rama de PHP con soporte activo (consulte php.net/supported-versions) "
                               "tras probar tema y plugins en un entorno de pruebas.",
                references=["https://www.php.net/supported-versions.php"], effort="Medio",
                evidence=[f"Versión detectada: PHP/{ctx.r.meta['php_version']}", f"Fin de soporte de seguridad: {eol or 'anterior a 2022'}"]))

    # --- WAF / CDN / seguridad perimetral ---
    waf = []
    if "cf-ray" in h or "cloudflare" in server.lower():
        waf.append("Cloudflare")
    if "x-sucuri-id" in h:
        waf.append("Sucuri")
    if "x-akamai-transformed" in h or "akamai" in server.lower():
        waf.append("Akamai")
    if "x-amz-cf-id" in h:
        waf.append("Amazon CloudFront")
    # --- Hosting gestionado (WordPress.com / Automattic) ---
    if "wordpress.com" in h.get("host-header", "").lower() or "x-nananana" in h or "x-ac" in h:
        ctx.r.meta["hosting"] = "WordPress.com / Automattic (alojamiento gestionado)"
        ctx.r.note("El sitio está alojado en WordPress.com (Automattic). La configuración del servidor (cabeceras HTTP, "
                   "wp-cron, TLS, listados, métodos HTTP) la gestiona el proveedor: algunas recomendaciones solo pueden "
                   "aplicarse mediante el soporte/plan del proveedor, un plugin o un CDN/WAF delante del sitio.")
    if waf:
        ctx.r.meta["cdn_waf"] = waf
        ctx.r.positive("Protección perimetral/CDN detectada: " + ", ".join(waf) + ".")
        ctx.r.note("Hay CDN/WAF delante del sitio: los resultados de puertos y de algunas pruebas reflejan al proveedor, no al servidor de origen.")


def check_cookies(ctx: Ctx) -> None:
    if ctx.home is None:
        return
    raw = []
    try:
        raw = ctx.home.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        pass
    problems = []
    for ck in raw:
        name = ck.split("=", 1)[0].strip()
        low = ck.lower()
        flags = []
        if ctx.c.scheme == "https" and "secure" not in low:
            flags.append("Secure")
        if "httponly" not in low and name != "wordpress_test_cookie":
            flags.append("HttpOnly")
        if "samesite" not in low:
            flags.append("SameSite")
        if flags:
            problems.append(f"Cookie '{name}' sin: {', '.join(flags)}")
    if problems:
        ctx.r.add(Finding(
            id="COOKIE-FLAGS", title="Cookies sin atributos de seguridad", severity="low", category="Sesiones y cookies",
            description="Algunas cookies no usan Secure, HttpOnly o SameSite, lo que facilita su robo o uso en ataques CSRF/XSS.",
            recommendation="Configure los atributos en el servidor, plugin de caché o aplicación que emite la cookie.",
            references=[OWASP_WSTG], effort="Bajo", evidence=problems))


# =============================================================================
# 4. Versión de WordPress y componentes
# =============================================================================
def detect_wp_version(ctx: Ctx) -> None:
    if not ctx.is_wp:
        return
    ev, version = [], None
    m = re.search(r'<meta name="generator" content="WordPress ([\d.]+)', ctx.html, re.I)
    if m:
        version = m.group(1)
        ev.append(f"Meta generator en la portada: WordPress {version}")
    if not version:
        r = ctx.c.get("/feed/")
        if r is not None and r.status_code == 200:
            m = re.search(r"wordpress\.org/\?v=([\d.]+)", r.text)
            if m:
                version = m.group(1)
                ev.append(f"Feed RSS expone generator: {version}")
    r = ctx.c.get("/readme.html")
    if r is not None and r.status_code == 200 and not ctx.is_soft404(r):
        m = re.search(r"Version\s+([\d.]+)", r.text)
        if m:
            version = version or m.group(1)
            ev.append(f"/readme.html accesible (versión {m.group(1)})")
    if not version:
        vers = re.findall(r"/wp-includes/[^\"'\s]+\?ver=(\d+\.\d+(?:\.\d+)?)", ctx.blob())
        if vers:
            version = max(set(vers), key=vers.count)
            ev.append(f"Inferida de parámetros ?ver= en recursos de wp-includes: {version}")
    ctx.wp_version = version
    ctx.r.meta["wp_version"] = version
    if ev:
        ctx.r.add(Finding(
            id="WP-VERSION-EXPOSED", title="La versión de WordPress es visible públicamente", severity="low",
            category="Divulgación de información",
            description="Conocer la versión exacta permite a un atacante buscar exploits específicos. No es una vulnerabilidad "
                        "por sí sola, pero facilita el reconocimiento.",
            recommendation="Elimine el meta generator, bloquee readme.html/license.txt y mantenga WordPress actualizado.",
            fix="// functions.php (o plugin de ajustes)\nremove_action('wp_head', 'wp_generator');\nadd_filter('the_generator', '__return_empty_string');\n\n"
                "# Apache: bloquear archivos informativos\n<FilesMatch \"^(readme\\.html|license\\.txt)$\">\n  Require all denied\n</FilesMatch>",
            references=[WP_HARDENING], effort="Bajo", evidence=ev))
    if not version:
        return
    try:
        data = wp_api("core/version-check/1.7/")
        ctx.r.cover("Versiones (api.wordpress.org)", "completa")
        latest = data["offers"][0]["current"]
        ctx.r.meta["wp_latest"] = latest
    except Exception as exc:  # noqa: BLE001
        ctx.online_api_ok = False
        ctx.r.cover("Versiones (api.wordpress.org)", "no evaluada", "Sin acceso a api.wordpress.org: verifique manualmente el núcleo, los plugins y los temas.")
        ctx.r.note(f"No se pudo consultar api.wordpress.org para comparar versiones ({type(exc).__name__}). "
                   "Verifique manualmente versiones de núcleo, plugins y temas.")
        return
    iv, lv = vkey(version), vkey(latest)
    if iv >= lv:
        ctx.r.positive(f"WordPress está en la última versión ({version}).")
        return
    same_branch = iv[:2] == lv[:2]
    gap = (lv[1] - iv[1]) if iv[0] == lv[0] and len(iv) > 1 and len(lv) > 1 else 3
    sev = "high" if (same_branch or gap >= 3) else "medium"
    ctx.r.add(Finding(
        id="WP-CORE-OUTDATED", title=f"WordPress desactualizado ({version}; última {latest})", severity=sev,
        category="Actualizaciones",
        description="El núcleo de WordPress no está en la última versión. Las versiones nuevas corrigen vulnerabilidades "
                    "publicadas; verifique si su rama todavía recibe parches de seguridad.",
        business_impact="Las vulnerabilidades conocidas del núcleo son explotadas masivamente de forma automatizada.",
        recommendation="Realice una copia de seguridad completa y actualice WordPress. Active las actualizaciones "
                       "automáticas de seguridad menores.",
        fix="// wp-config.php\ndefine('WP_AUTO_UPDATE_CORE', 'minor'); // o true para todas las versiones",
        references=["https://wordpress.org/download/releases/", WP_HARDENING], effort="Medio",
        evidence=[f"Instalada: {version}", f"Última estable: {latest}"]))


def _api_lookup(path: str, params: dict | None = None):
    """Devuelve la ficha, None si el componente no está en wordpress.org, o ApiUnavailable si no hubo respuesta."""
    try:
        d = wp_api(path, params)
    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 404:
            return None
        raise ApiUnavailable from exc
    except (requests.RequestException, ValueError) as exc:
        raise ApiUnavailable from exc
    return d if isinstance(d, dict) and "version" in d else None


def _api_plugin(slug: str):
    return _api_lookup(f"plugins/info/1.0/{slug}.json")


def _api_theme(slug: str):
    return _api_lookup("themes/info/1.2/", {"action": "theme_information", "request[slug]": slug})


def _lookup_or_gap(ctx: Ctx, fn, slug: str):
    try:
        return True, fn(slug)
    except ApiUnavailable:
        ctx.online_api_ok = False
        ctx.r.cover("Versiones (api.wordpress.org)", "no evaluada", "Sin acceso a api.wordpress.org: verifique manualmente el núcleo, los plugins y los temas.")
        return False, None


# Plugins comunes o con historial de fallos graves que no siempre aparecen en el HTML público.
COMMON_PLUGINS = (
    "advanced-custom-fields", "akismet", "all-in-one-wp-migration", "all-in-one-wp-security-and-firewall",
    "backwpup", "better-wp-security", "contact-form-7", "duplicator", "easy-wp-smtp", "elementor",
    "essential-addons-for-elementor-lite", "file-manager", "iwp-client", "jetpack", "js_composer", "LayerSlider",
    "litespeed-cache", "loginizer", "mailchimp-for-wp", "nextgen-gallery", "ninja-forms", "really-simple-ssl",
    "redirection", "revslider", "social-warfare", "sucuri-scanner", "tablepress", "updraftplus", "w3-total-cache",
    "woocommerce", "wordfence", "wordpress-seo", "wp-advanced-search", "wp-fastest-cache", "wp-file-manager",
    "wp-file-upload", "wp-super-cache", "wp-time-capsule", "wpforms-lite",
)


def readme_version(text: str) -> str | None:
    """Versión de un readme.txt: usa Stable tag y, si dice trunk, la primera entrada del changelog."""
    m = re.search(r"^\s*Stable tag:\s*[\"']?v?(\d[\w.\-]*)", text, re.I | re.M)
    if m:
        return m.group(1)
    changelog = re.split(r"^==\s*Changelog\s*==", text, maxsplit=1, flags=re.I | re.M)
    if len(changelog) == 2:
        m = re.search(r"^=+\s*v?(\d+(?:\.\d+)+)", changelog[1], re.M)
        if m:
            return m.group(1)
    return None


def _is_plugin_readme(ctx: Ctx, r) -> bool:
    return (r is not None and r.status_code == 200 and not ctx.is_soft404(r)
            and bool(re.search(r"^===.+===|^\s*Stable tag:", r.text, re.I | re.M)))


def enum_components(ctx: Ctx) -> None:
    if not ctx.is_wp:
        return
    blob = ctx.blob()
    plugin_slugs = sorted(set(re.findall(r"/wp-content/plugins/([A-Za-z0-9_.\-]+)/", blob)))[:40]
    theme_slugs = sorted(set(re.findall(r"/wp-content/themes/([A-Za-z0-9_.\-]+)/", blob)))[:6]
    plugins, themes, readme_exposed = [], [], []
    today = dt.date.today()
    readmes = {}
    for slug in COMMON_PLUGINS:
        if slug not in plugin_slugs:
            r = ctx.c.get(f"/wp-content/plugins/{slug}/readme.txt")
            if _is_plugin_readme(ctx, r):
                readmes[slug] = r
                plugin_slugs.append(slug)

    for slug in plugin_slugs:
        item = {"slug": slug, "version": None, "latest": None, "status": "Desconocido",
                "last_updated": None, "installs": None}
        r = readmes.get(slug) or ctx.c.get(f"/wp-content/plugins/{slug}/readme.txt")
        if r is not None and r.status_code == 200 and not ctx.is_soft404(r):
            item["version"] = readme_version(r.text)
            readme_exposed.append(f"/wp-content/plugins/{slug}/readme.txt")
        if not item["version"]:
            vs = [v for v in re.findall(rf"/plugins/{re.escape(slug)}/[^\"'\s]*?\?ver=([\d.]+)", blob)
                  if v != ctx.wp_version]
            if vs:
                item["version"] = vs[0] + " (estimada)"
        if not ctx.online_api_ok:
            item["status"] = "No verificado"
        else:
            answered, api = _lookup_or_gap(ctx, _api_plugin, slug)
            if not answered:
                item["status"] = "No verificado"
            elif api:
                item["latest"] = api.get("version")
                item["installs"] = api.get("active_installs")
                lu = (api.get("last_updated") or "")[:10]
                item["last_updated"] = lu or None
                cur = (item["version"] or "").split(" ")[0]
                if cur and item["latest"] and vkey(cur) < vkey(item["latest"]):
                    item["status"] = "Desactualizado"
                elif cur:
                    item["status"] = "Al día"
                try:
                    if lu and (today - dt.date.fromisoformat(lu)).days > 730:
                        item["status"] = "Abandonado" if item["status"] != "Desactualizado" else "Desactualizado y abandonado"
                except ValueError:
                    pass
            else:
                item["status"] = "No listado (premium/personalizado/retirado)"
        plugins.append(item)

    for slug in theme_slugs:
        item = {"slug": slug, "version": None, "latest": None, "status": "Desconocido", "last_updated": None}
        r = ctx.c.get(f"/wp-content/themes/{slug}/style.css")
        if r is not None and r.status_code == 200 and not ctx.is_soft404(r):
            m = re.search(r"^\s*Version:\s*([\w.\-]+)", r.text, re.I | re.M)
            if m:
                item["version"] = m.group(1)
        if not ctx.online_api_ok:
            item["status"] = "No verificado"
        else:
            answered, api = _lookup_or_gap(ctx, _api_theme, slug)
            if not answered:
                item["status"] = "No verificado"
            elif api:
                item["latest"] = api.get("version")
                cur = item["version"] or ""
                if cur and item["latest"]:
                    item["status"] = "Desactualizado" if vkey(cur) < vkey(item["latest"]) else "Al día"
            else:
                item["status"] = "No listado (premium/hijo/personalizado)"
        themes.append(item)

    ctx.r.meta["plugins"] = plugins
    ctx.r.meta["themes"] = themes

    outdated = [p for p in plugins + themes if p["status"].startswith("Desactualizado")]
    abandoned = [p for p in plugins if "bandonado" in p["status"] or p["status"].endswith("abandonado")]
    if outdated:
        # Una versión "estimada" (por ?ver=) no basta para afirmar un salto mayor.
        confirmed_items = [p for p in outdated if "estimada" not in (p["version"] or "")]
        major = any(vkey((p["version"] or "0").split(" ")[0])[:1] != vkey(p["latest"])[:1] for p in confirmed_items)
        confirmed = bool(confirmed_items)
        # Versiones solo "estimadas" (por ?ver=) son poco fiables: si no hay salto mayor, severidad baja.
        sev_outdated = "high" if major else ("medium" if confirmed else "low")
        ctx.r.add(Finding(
            id="WP-COMP-OUTDATED", title=f"{len(outdated)} plugin(s)/tema(s) desactualizados",
            severity=sev_outdated, category="Actualizaciones",
            description="Los plugins y temas son la principal vía de compromiso de sitios WordPress. Las versiones antiguas "
                        "pueden contener vulnerabilidades ya publicadas.",
            business_impact="Un solo plugin vulnerable puede permitir la toma de control del sitio, robo de datos o inyección de malware/SEO spam.",
            recommendation="Actualice cada componente (primero en un entorno de pruebas), elimine los que no use y active "
                           "actualizaciones automáticas para los de confianza.",
            fix="// wp-config.php — actualizaciones automáticas (evalúe el riesgo de compatibilidad)\nadd_filter('auto_update_plugin', '__return_true');\nadd_filter('auto_update_theme', '__return_true');",
            references=["https://wpscan.com/", WP_HARDENING], effort="Medio",
            evidence=[f"{p['slug']}: instalada {p['version']} → última {p['latest']}" for p in outdated]))
    if abandoned:
        ctx.r.add(Finding(
            id="WP-COMP-ABANDONED", title=f"{len(abandoned)} plugin(s) sin actualizaciones desde hace más de 2 años",
            severity="medium", category="Actualizaciones",
            description="Un plugin sin mantenimiento no recibirá correcciones de seguridad cuando se descubran fallos.",
            business_impact="Riesgo creciente y permanente: cualquier vulnerabilidad futura quedará sin parche.",
            recommendation="Sustituya los plugins abandonados por alternativas mantenidas o elimínelos si no son esenciales.",
            references=[WP_HARDENING], effort="Medio",
            evidence=[f"{p['slug']} (última actualización: {p['last_updated']})" for p in abandoned]))
    if readme_exposed:
        ctx.r.add(Finding(
            id="WP-README-EXPOSED", title="Los readme.txt de los plugins son accesibles públicamente", severity="low",
            category="Divulgación de información",
            description="Los archivos readme.txt permiten a cualquiera conocer qué plugins y qué versiones exactas se usan.",
            recommendation="Bloquee el acceso a readme.txt/changelog en wp-content/plugins desde el servidor web.",
            fix="# Nginx\nlocation ~* ^/wp-content/plugins/.+/(readme|changelog)\\.(txt|md)$ { deny all; }\n\n"
                "# Apache\n<FilesMatch \"^(readme|changelog)\\.(txt|md)$\">\n  Require all denied\n</FilesMatch>",
            references=[WP_HARDENING], effort="Bajo", evidence=readme_exposed[:10]))

    sec_plugins = {"wordfence", "sucuri-scanner", "better-wp-security", "all-in-one-wp-security-and-firewall",
                   "wp-2fa", "two-factor", "limit-login-attempts-reloaded", "wp-cerber", "ninjafirewall"}
    found = [p["slug"] for p in plugins if p["slug"] in sec_plugins]
    if found:
        ctx.r.positive("Plugin(s) de seguridad detectados: " + ", ".join(found) + ".")


# =============================================================================
# 5. Usuarios, XML-RPC y superficie de acceso
# =============================================================================
def check_users(ctx: Ctx) -> None:
    if not ctx.is_wp:
        return
    users, ev = {}, []
    conclusive = True
    for path in ("/wp-json/wp/v2/users?per_page=20", "/?rest_route=/wp/v2/users&per_page=20"):
        r = ctx.c.get(path)
        conclusive = conclusive and ctx.conclusive(r)
        if r is not None and r.status_code == 200 and "json" in r.headers.get("Content-Type", ""):
            try:
                for u in r.json():
                    users[u.get("slug") or u.get("name")] = u.get("name")
                if users:
                    ev.append(f"GET {path.split('?')[0]} → {len(users)} usuario(s) listados sin autenticación")
                    break
            except (ValueError, AttributeError, TypeError):
                pass
    for i in (1, 2, 3):
        r = ctx.c.get(f"/?author={i}", follow=False)
        conclusive = conclusive and ctx.conclusive(r)
        if r is not None and r.status_code in (301, 302):
            m = re.search(r"/author/([^/]+)/?", r.headers.get("Location", ""))
            if m:
                users.setdefault(m.group(1), None)
                ev.append(f"/?author={i} redirige a /author/{m.group(1)}/")
    ctx.r.meta["users"] = sorted(users.keys())
    if users:
        ctx.r.add(Finding(
            id="USR-ENUM", title="Enumeración de nombres de usuario posible", severity="medium",
            category="Autenticación",
            description="Es posible obtener nombres de usuario válidos sin autenticarse (REST API y/o archivos de autor). "
                        "Esto facilita los ataques de fuerza bruta y de credential stuffing.",
            business_impact="Los atacantes pueden dirigir ataques de contraseñas contra cuentas reales, incluidas las de administración.",
            recommendation="Restrinja el endpoint /wp/v2/users a usuarios autenticados, bloquee ?author=N y use 2FA en cuentas con privilegios.",
            fix="// functions.php\nadd_filter('rest_endpoints', function ($e) {\n  if (!is_user_logged_in()) {\n    unset($e['/wp/v2/users'], $e['/wp/v2/users/(?P<id>[\\d]+)']);\n  }\n  return $e;\n});\n\n"
                "# Apache: bloquear enumeración por ?author=\nRewriteCond %{QUERY_STRING} (^|&)author=\\d+ [NC]\nRewriteRule ^ - [F]",
            references=[OWASP_WSTG + "latest/4-Web_Application_Security_Testing/03-Identity_Management_Testing/04-Testing_for_Account_Enumeration_and_Guessable_User_Account"],
            effort="Bajo", evidence=ev + ["Usuarios expuestos: " + ", ".join(sorted(users.keys()))]))
        weak = [u for u in users if u.lower() in ("admin", "administrator", "root", "wordpress", "test")]
        if weak:
            ctx.r.add(Finding(
                id="USR-PREDICTABLE", title="Existen nombres de usuario predecibles", severity="low",
                category="Autenticación",
                description="Cuentas con nombres como 'admin' son el primer objetivo de ataques automatizados.",
                recommendation="Cree un administrador con nombre no predecible, reasigne el contenido y elimine la cuenta predecible.",
                effort="Bajo", references=[WP_HARDENING], evidence=[f"Usuario: {u}" for u in weak]))
    elif conclusive:
        ctx.r.positive("No se pudo enumerar usuarios de forma anónima (REST y ?author=).")
    else:
        ctx.r.cover("Enumeración de usuarios", "no evaluada", "El servidor no respondió o limitó las peticiones.")


def check_xmlrpc(ctx: Ctx) -> None:
    if not ctx.is_wp:
        return
    body = '<?xml version="1.0"?><methodCall><methodName>system.listMethods</methodName><params></params></methodCall>'
    r = ctx.c.post("/xmlrpc.php", data=body, headers={"Content-Type": "text/xml"})
    if r is not None and r.status_code in (401, 403, 404, 405, 410):
        ctx.r.positive(f"XML-RPC deshabilitado o bloqueado (HTTP {r.status_code}).")
        return
    if r is None or r.status_code != 200 or "methodResponse" not in r.text:
        ctx.r.cover("XML-RPC", "no evaluada", "La respuesta no permite confirmar si está habilitado.")
        return
    methods = re.findall(r"<string>([^<]+)</string>", r.text)
    risky = [m for m in ("system.multicall", "pingback.ping") if m in methods]
    ctx.r.meta["xmlrpc_methods"] = len(methods)
    ctx.r.add(Finding(
        id="XMLRPC-ENABLED", title="XML-RPC habilitado" + (" con métodos de riesgo" if risky else ""),
        severity="medium" if risky else "low", category="Superficie de ataque",
        description="xmlrpc.php permite probar cientos de contraseñas en una sola petición (system.multicall) y "
                    "usar el sitio como pivote en ataques de denegación de servicio (pingback.ping).",
        business_impact="Facilita la fuerza bruta evadiendo límites de intentos de login y el abuso del servidor.",
        recommendation="Desactive XML-RPC si no usa Jetpack, la app móvil de WordPress o integraciones que lo requieran.",
        fix="// functions.php\nadd_filter('xmlrpc_enabled', '__return_false');\n\n# Apache\n<Files xmlrpc.php>\n  Require all denied\n</Files>\n\n# Nginx\nlocation = /xmlrpc.php { deny all; }",
        references=[WP_HARDENING], effort="Bajo",
        evidence=[f"POST /xmlrpc.php system.listMethods → {len(methods)} métodos", *[f"Método expuesto: {m}" for m in risky]]))


def check_login_surface(ctx: Ctx) -> None:
    if not ctx.is_wp:
        return
    r = ctx.c.get("/wp-login.php")
    if r is not None and r.status_code == 200 and "user_login" in r.text:
        has_captcha = bool(re.search(r"g-recaptcha|h-captcha|cf-turnstile|captcha", r.text, re.I))
        ctx.r.meta["login_exposed"] = True
        if has_captcha:
            ctx.r.positive("El formulario de login incorpora CAPTCHA.")
        ctx.r.add(Finding(
            id="LOGIN-EXPOSED", title="Panel de acceso (wp-login.php) expuesto a Internet", severity="low",
            category="Autenticación",
            description="El formulario de login es accesible desde cualquier IP. Es el punto de entrada de la mayoría de "
                        "ataques de fuerza bruta contra WordPress." + ("" if has_captcha else " No se detectó CAPTCHA."),
            business_impact="Intentos masivos de adivinar contraseñas; si prospera uno, el atacante controla el sitio.",
            recommendation="Active 2FA para administradores/editores, limite intentos fallidos, use contraseñas únicas largas "
                           "y, si es posible, restrinja /wp-admin por IP o detrás de VPN/WAF. (No se probaron contraseñas durante esta auditoría.)",
            fix="# Apache — restringir wp-login por IP\n<Files wp-login.php>\n  Require ip 203.0.113.10\n</Files>\n\n# Nginx\nlocation = /wp-login.php { allow 203.0.113.10; deny all; fastcgi_pass ...; }",
            references=[WP_HARDENING], effort="Bajo"))
    r = ctx.c.get("/wp-login.php?action=register")
    if r is not None and r.status_code == 200 and "registerform" in r.text:
        ctx.r.add(Finding(
            id="REG-OPEN", title="Registro público de usuarios habilitado", severity="medium",
            category="Autenticación",
            description="Cualquier persona puede crear una cuenta. Si el rol por defecto no es 'Suscriptor' o hay plugins con "
                        "fallos de escalada de privilegios, el riesgo aumenta.",
            recommendation="Desactive 'Cualquiera puede registrarse' (Ajustes → Generales) si no lo necesita; si lo necesita, "
                           "mantenga el rol por defecto como Suscriptor y añada CAPTCHA/verificación de email.",
            references=[WP_HARDENING], effort="Bajo", evidence=["GET /wp-login.php?action=register → formulario de registro disponible"]))


# =============================================================================
# 6. Archivos y directorios sensibles
# =============================================================================
BACKUP_NOTE = "Retire el archivo del directorio web, rote TODAS las credenciales afectadas y revise los registros de acceso por descargas previas."

SENSITIVE = [
    dict(id="FILE-WPCONFIG", sev="critical", title="Copia de wp-config.php accesible públicamente",
         paths=["wp-config.php.bak", "wp-config.php.old", "wp-config.php.save", "wp-config.php.orig",
                "wp-config.php~", "wp-config.txt", "wp-config.php.swp", "wp-config.bak", "wp-config.php.txt"],
         sig=r"DB_PASSWORD|DB_NAME|AUTH_KEY", cat="Exposición de archivos",
         desc="Se puede descargar un respaldo del archivo de configuración con credenciales de base de datos y claves de seguridad.",
         impact="Compromiso total: acceso a la base de datos, posible toma de control del sitio y de los datos de usuarios.",
         rec=BACKUP_NOTE + " Cambie las salts/keys de wp-config.php y la contraseña de la base de datos."),
    dict(id="FILE-ENV", sev="critical", title="Archivo .env accesible públicamente", paths=[".env", ".env.bak", ".env.production"],
         sig=r"(DB_|APP_KEY|SECRET|PASSWORD|API_KEY|TOKEN)[A-Z_]*\s*=", cat="Exposición de archivos",
         desc="Un archivo de variables de entorno con secretos es descargable.",
         impact="Fuga de credenciales y claves de API de terceros.", rec=BACKUP_NOTE),
    dict(id="FILE-GIT", sev="high", title="Repositorio .git expuesto", paths=[".git/HEAD", ".git/config"],
         sig=r"^ref: refs/|\[core\]", cat="Exposición de archivos",
         desc="El directorio .git es accesible: es posible reconstruir el código fuente y el historial, que puede contener secretos.",
         impact="Fuga de código propietario y credenciales históricas.",
         rec="Bloquee el acceso a directorios ocultos en el servidor web y elimine .git del directorio público.",
         fix="# Nginx\nlocation ~ /\\.(?!well-known) { deny all; }\n\n# Apache\nRedirectMatch 404 /\\.git"),
    dict(id="FILE-DEBUGLOG", sev="high", title="Registro de depuración de WordPress accesible", paths=["wp-content/debug.log"],
         sig=r"PHP (Warning|Notice|Fatal|Deprecated)|\[\d{2}-\w{3}-\d{4}", cat="Exposición de archivos",
         desc="debug.log es público y puede revelar rutas del servidor, consultas SQL, errores y datos de usuarios.",
         impact="Información valiosa para preparar ataques dirigidos.",
         rec="Elimine el archivo, desactive WP_DEBUG_LOG en producción o redirija el log fuera del directorio web.",
         fix="// wp-config.php (producción)\ndefine('WP_DEBUG', false);\ndefine('WP_DEBUG_DISPLAY', false);\ndefine('WP_DEBUG_LOG', '/var/log/wordpress/debug.log');"),
    dict(id="FILE-PHPINFO", sev="high", title="Página phpinfo expuesta", paths=["phpinfo.php", "info.php", "php.php", "test.php"],
         sig=r"phpinfo\(\)|<title>phpinfo|PHP Version \d", cat="Exposición de archivos",
         desc="phpinfo() revela configuración completa del servidor, módulos, rutas y variables de entorno.",
         impact="Facilita ataques dirigidos y puede filtrar secretos de entorno.", rec="Elimine estos archivos de producción."),
    dict(id="FILE-ERRORLOG", sev="medium", title="Registros de error de PHP accesibles", paths=["error_log", "php_errorlog", "wp-admin/error_log", "wp-content/error_log"],
         sig=r"PHP (Warning|Notice|Fatal|Parse)|\[\d{2}-\w{3}-\d{4}", cat="Exposición de archivos",
         desc="Archivos de log con rutas internas y mensajes de error son descargables.", impact="Divulgación de información interna.",
         rec="Elimine los logs del directorio público y configure el servidor para escribirlos fuera de él."),
    dict(id="FILE-INSTALL", sev="critical", title="Instalador de WordPress accesible y sin completar", paths=["wp-admin/install.php", "wp-admin/setup-config.php"],
         sig=r"(Welcome|Bienvenido).{0,200}(famous|famoso|five-minute)|name=\"weblog_title\"|Let.s go|Vamos a ello|name=\"dbname\"",
         cat="Exposición de archivos", desc="El asistente de instalación está disponible; un atacante podría instalar el sitio con sus propias credenciales.",
         impact="Toma de control total del sitio.", rec="Complete/restablezca la instalación de inmediato y verifique que wp-config.php exista y sea correcto."),
    dict(id="FILE-BACKUP", sev="critical", title="Respaldos o volcados de base de datos descargables",
         paths=["backup.zip", "backup.sql", "db.sql", "dump.sql", "database.sql", "site.zip", "wordpress.zip", "public_html.zip",
                "www.zip", "backup.tar.gz", "wp-content/backup-db/", "wp-content/uploads/backup.zip"],
         sig=r"CREATE TABLE|INSERT INTO|-- MySQL dump|^PK\x03\x04|^\x1f\x8b", cat="Exposición de archivos",
         desc="Se encontraron archivos de respaldo o volcados SQL en rutas públicas.",
         impact="Fuga completa de datos: usuarios, hashes de contraseñas, contenido y configuración.", rec=BACKUP_NOTE),
    dict(id="DIR-BACKUPPLUGINS", sev="high", title="Directorio de respaldos de plugins listable", paths=["wp-content/updraft/", "wp-content/ai1wm-backups/", "wp-content/backups/", "wp-content/backupwordpress/"],
         sig=r"<title>Index of /|Directory listing for", cat="Exposición de archivos",
         desc="Plugins de respaldo guardan copias en directorios públicos.", impact="Descarga de copias completas del sitio.",
         rec="Mueva los respaldos fuera del directorio web o proteja la carpeta con denegación de acceso."),
    dict(id="DIR-LISTING", sev="medium", title="Listado de directorios habilitado",
         paths=["wp-content/uploads/", "wp-content/plugins/", "wp-content/themes/", "wp-includes/", "wp-content/"],
         sig=r"<title>Index of /|Directory listing for", cat="Configuración del servidor",
         desc="El servidor muestra el contenido de directorios, revelando archivos que no deberían ser descubribles.",
         impact="Divulgación de ficheros internos, plugins instalados y posibles archivos sensibles subidos.",
         rec="Desactive el autoindex en el servidor web.", fix="# Apache (.htaccess)\nOptions -Indexes\n\n# Nginx\nautoindex off;"),
    dict(id="FILE-HTACCESS", sev="medium", title=".htaccess accesible públicamente", paths=[".htaccess"],
         sig=r"RewriteEngine|<IfModule|RewriteRule", cat="Configuración del servidor",
         desc="El archivo de reglas del servidor es legible desde Internet.", impact="Revela reglas de reescritura, rutas ocultas y protecciones.",
         rec="Bloquee el acceso a archivos que comienzan por punto."),
    dict(id="FILE-DBTOOLS", sev="high", title="Herramienta de administración de bases de datos expuesta", paths=["phpmyadmin/", "pma/", "adminer.php", "adminer/"],
         sig=r"phpMyAdmin|pma_|Adminer", cat="Superficie de ataque",
         desc="Se encontró una interfaz de administración de bases de datos accesible públicamente.",
         impact="Un fallo o una credencial débil permitiría acceso directo a todos los datos.",
         rec="Elimínela del servidor público o restrinja su acceso por IP/VPN y autenticación adicional."),
    dict(id="FILE-SERVERSTATUS", sev="medium", title="Página de estado del servidor expuesta", paths=["server-status", "server-info"],
         sig=r"Apache Server Status|Apache Server Information", cat="Configuración del servidor",
         desc="mod_status/mod_info accesible públicamente.", impact="Revela URLs solicitadas, IPs de clientes y carga del servidor.",
         rec="Restrinja a localhost o a IPs de administración.", fix="<Location \"/server-status\">\n  Require local\n</Location>"),
    dict(id="FILE-COMPOSER", sev="low", title="Archivos de dependencias accesibles", paths=["composer.json", "composer.lock", "package.json", "package-lock.json"],
         sig=r"\"(require|dependencies|packages)\"", cat="Exposición de archivos",
         desc="Los manifiestos de dependencias revelan librerías y versiones usadas.", impact="Facilita la búsqueda de vulnerabilidades en dependencias.",
         rec="Bloquee estos archivos o manténgalos fuera del directorio público."),
]


def _matches(sig: str, resp) -> bool:
    if re.search(r"\\x|\^PK", sig):
        head = resp.content[:1024]
        if re.search(rb"CREATE TABLE|INSERT INTO|-- MySQL dump", head):
            return True
        return head.startswith(b"PK\x03\x04") or head.startswith(b"\x1f\x8b")
    text = resp.content[:20000].decode("utf-8", "replace")
    return bool(re.search(sig, text, re.I | re.M))


def check_sensitive_files(ctx: Ctx) -> None:
    for spec in SENSITIVE:
        hits = []
        for path in spec["paths"]:
            r = ctx.c.get("/" + path, headers={"Range": "bytes=0-20000"})
            if r is None or r.status_code not in (200, 206) or ctx.is_soft404(r):
                continue
            ctype = r.headers.get("Content-Type", "")
            if spec["id"] == "FILE-BACKUP" and "text/html" in ctype and not path.endswith("/"):
                continue
            if _matches(spec["sig"], r):
                size = r.headers.get("Content-Range", "").split("/")[-1] or str(len(r.content))
                hits.append(f"GET /{path} → HTTP {r.status_code} ({size} bytes; contenido omitido por seguridad)")
        if hits:
            ctx.r.add(Finding(
                id=spec["id"], title=spec["title"], severity=spec["sev"], category=spec["cat"],
                description=spec["desc"], business_impact=spec.get("impact", ""), recommendation=spec["rec"],
                fix=spec.get("fix", ""), references=[WP_HARDENING, OWASP_WSTG], effort="Bajo", evidence=hits))

    # wp-cron.php
    r = ctx.c.get("/wp-cron.php")
    if ctx.is_wp and r is not None and r.status_code == 200 and not ctx.is_soft404(r):
        ctx.r.add(Finding(
            id="WP-CRON", title="wp-cron.php accesible públicamente", severity="low", category="Superficie de ataque",
            description="Cada visita puede disparar wp-cron.php; llamarlo masivamente consume recursos (DoS de bajo costo).",
            recommendation="Desactive el cron por visita y programe una tarea real del sistema cada 5–15 minutos.",
            fix="// wp-config.php\ndefine('DISABLE_WP_CRON', true);\n\n# crontab\n*/10 * * * * curl -s https://SU-SITIO/wp-cron.php?doing_wp_cron >/dev/null 2>&1",
            references=[WP_HARDENING], effort="Bajo", evidence=["GET /wp-cron.php → HTTP 200"]))


# =============================================================================
# 7. Otras comprobaciones
# =============================================================================
def check_misc(ctx: Ctx) -> None:
    c = ctx.c
    # CORS
    # El núcleo de WordPress refleja el Origin en /wp-json/ por diseño (rest_send_cors_headers) y las
    # peticiones autenticadas por cookie exigen un nonce, así que ahí NO es una vulnerabilidad por sí solo.
    # Sí es grave si ocurre en páginas normales u otros endpoints.
    evil = {"Origin": "https://evil.example"}
    cors_hits = {}
    for path in ("/", "/wp-json/"):
        r = c.get(path, headers=evil)
        if r is not None:
            acao = r.headers.get("Access-Control-Allow-Origin", "")
            acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
            if acao == "https://evil.example" and acac == "true":
                cors_hits[path] = f"GET {path} con Origin: https://evil.example → ACAO: {acao}, ACAC: {acac}"
    if "/" in cors_hits:
        ctx.r.add(Finding(
            id="CORS-REFLECT", title="CORS refleja orígenes arbitrarios con credenciales", severity="high",
            category="Configuración del servidor",
            description="El servidor acepta cualquier Origin y permite credenciales en páginas normales, habilitando lectura de datos autenticados desde sitios maliciosos.",
            recommendation="Use una lista blanca de orígenes y nunca combine orígenes reflejados con Allow-Credentials.",
            references=[OWASP_WSTG], effort="Medio", evidence=list(cors_hits.values())))
    elif cors_hits:
        ctx.r.add(Finding(
            id="CORS-REST", title="La REST API refleja el Origin y permite credenciales (comportamiento estándar de WordPress)",
            severity="low", category="Configuración del servidor",
            description="El endpoint /wp-json/ devuelve Access-Control-Allow-Origin igual al Origin recibido y Allow-Credentials: true. "
                        "Es el comportamiento por defecto del núcleo de WordPress; las acciones autenticadas por cookie exigen además un "
                        "nonce, por lo que no permite leer datos de un usuario desde otro sitio. Se informa como endurecimiento opcional.",
            recommendation="Si no usa la REST API desde otros dominios, restrinja los orígenes permitidos con el filtro rest_pre_serve_request "
                           "o desde el servidor/CDN.",
            references=["https://developer.wordpress.org/rest-api/"], effort="Bajo", evidence=list(cors_hits.values())))
    # Métodos HTTP
    try:
        c.result.requests_made += 1
        time.sleep(c.delay)
        o = c.s.options(c.url("/"), timeout=c.timeout)
        allow = o.headers.get("Allow", "")
        bad = [m for m in ("TRACE", "PUT", "DELETE", "CONNECT") if m in allow.upper()]
        if bad:
            ctx.r.add(Finding(
                id="HTTP-METHODS", title="Métodos HTTP innecesarios habilitados", severity="low",
                category="Configuración del servidor", description="El servidor anuncia métodos que normalmente no se usan en un sitio web.",
                recommendation="Deshabilite métodos no necesarios (TRACE, PUT, DELETE, CONNECT).",
                references=[OWASP_WSTG], effort="Bajo", evidence=[f"Allow: {allow}"]))
    except requests.RequestException:
        pass
    # Contenido mixto y SRI
    if c.scheme == "https":
        # Solo recursos que el navegador realmente carga: src= y hojas de estilo. Se ignoran enlaces
        # como <link rel="profile" href="http://gmpg.org/xfn/11"> o <a href>, que no son contenido mixto.
        mixed = re.findall(r"""\ssrc=["'](http://[^"']+)["']""", ctx.html, re.I)
        for tag in re.findall(r"<link\b[^>]*>", ctx.html, re.I):
            if re.search(r"""rel=["'][^"']*stylesheet""", tag, re.I):
                m = re.search(r"""href=["'](http://[^"']+)["']""", tag, re.I)
                if m:
                    mixed.append(m.group(1))
        scripts = [m for m in mixed if re.search(r"\.(js|css)(\?|$)", m)]
        if mixed:
            ctx.r.add(Finding(
                id="MIXED-CONTENT", title="Contenido mixto (recursos HTTP en página HTTPS)",
                severity="medium" if scripts else "low", category="Transporte",
                description="La página carga recursos por HTTP sin cifrar; los navegadores pueden bloquearlos y un atacante podría alterarlos.",
                recommendation="Actualice las URLs a https:// (Ajustes → Generales, buscar-reemplazar en base de datos, revisar tema/plugins).",
                references=[OWASP_WSTG], effort="Bajo", evidence=mixed[:8]))
    no_sri = []
    for tag in re.findall(r"<script[^>]+src=[\"']https?://[^>]+>", ctx.html, re.I):
        m = re.search(r"""src=["']https?://([^/"']+)""", tag)
        if m and m.group(1) not in c.allowed and "integrity=" not in tag.lower():
            no_sri.append(m.group(1))
    if no_sri:
        ctx.r.add(Finding(
            id="SRI-MISSING", title="Scripts de terceros sin Subresource Integrity (SRI)", severity="low",
            category="Cadena de suministro",
            description="Se cargan scripts externos sin verificación de integridad; si el proveedor se compromete, su sitio ejecutará código malicioso.",
            recommendation="Añada atributos integrity/crossorigin a scripts estáticos de terceros o aloje una copia propia.",
            references=["https://developer.mozilla.org/docs/Web/Security/Subresource_Integrity"], effort="Medio",
            evidence=sorted(set(no_sri))[:10]))
    ctx.r.meta["third_party_hosts"] = sorted(set(re.findall(r"""(?:src|href)=["']https?://([^/"']+)""", ctx.html)) - c.allowed)[:25]
    # security.txt
    r = c.get("/.well-known/security.txt")
    if r is None or r.status_code != 200 or "Contact" not in r.text:
        ctx.r.add(Finding(
            id="SECTXT-MISSING", title="No existe security.txt", severity="info", category="Gobernanza",
            description="No hay un canal publicado (RFC 9116) para que investigadores reporten vulnerabilidades de forma responsable.",
            recommendation="Publique /.well-known/security.txt con un contacto de seguridad.",
            fix="Contact: mailto:seguridad@su-dominio.com\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: es, en",
            references=["https://www.rfc-editor.org/rfc/rfc9116"], effort="Bajo"))
    else:
        ctx.r.positive("Existe security.txt para reportes de vulnerabilidades.")


CHECKS = [
    ("Acceso inicial y rastreo", fetch_home),
    ("Calibración anti falsos positivos", calibrate),
    ("Detección de WordPress", detect_is_wordpress),
    ("Transporte HTTPS", check_transport),
    ("Análisis TLS", check_tls),
    ("Cabeceras HTTP", check_headers),
    ("Cookies", check_cookies),
    ("Versión de WordPress", detect_wp_version),
    ("Plugins y temas", enum_components),
    ("Enumeración de usuarios", check_users),
    ("XML-RPC", check_xmlrpc),
    ("Superficie de login", check_login_surface),
    ("Archivos sensibles", check_sensitive_files),
    ("Otras comprobaciones", check_misc),
]


def run_builtin(ctx: Ctx, log) -> None:
    for name, fn in CHECKS:
        log(f"[+] {name}")
        try:
            fn(ctx)
        except RuntimeError as exc:
            if fn is fetch_home:
                raise
            ctx.r.note(f"{name}: {exc}")
            ctx.r.cover(name, "no evaluada", str(exc))
        except Exception as exc:  # noqa: BLE001  (un chequeo roto no debe tumbar la auditoría)
            ctx.r.note(f"{name}: error interno ({type(exc).__name__}: {exc})")
            ctx.r.cover(name, "no evaluada", "Error interno de la comprobación.")
    if ctx.c.limited or ctx.c.failed:
        ctx.r.cover("Respuestas del servidor", "parcial",
                    f"Respuestas 429/5xx: {ctx.c.limited}; peticiones sin respuesta: {ctx.c.failed}: un WAF o el hosting pudo ocultar hallazgos.")
    if ctx.c.tls_problem:
        ctx.r.add(Finding(
            id="TLS-CERT", title="Certificado TLS inválido o no confiable", severity="high", category="Transporte",
            description="La conexión HTTPS falló la verificación del certificado durante la auditoría.",
            recommendation="Instale un certificado válido emitido por una CA reconocida.", effort="Bajo",
            evidence=[ctx.c.tls_problem]))
