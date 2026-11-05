import os
import subprocess
import sys
from pathlib import Path
import json
import stat

import pytest

from wpaudit import __version__, checks, external
from wpaudit.cli import main
from wpaudit.models import AuditResult, Finding
from wpaudit.report import write_reports

HOME = '<html><meta name="generator" content="WordPress 6.0"><a href="/fuera/">x</a></html>'
BASE = ["--authorized", "--profile", "quick", "--no-pdf", "--delay", "0"]


def result_with(*severities):
    result = AuditResult("https://x", "x", "2026-01-01T00:00:00")
    for i, severity in enumerate(severities):
        result.add(Finding(id=str(i), title="t", severity=severity, category="c", description="d", recommendation="r"))
    return result


def only_report(output):
    return json.loads(next(output.glob("*/resultados.json")).read_text(encoding="utf-8"))


def test_critical_finding_always_fails_the_grade():
    assert result_with("critical").grade()[0] == "F"


def test_high_finding_cannot_get_a_good_grade():
    assert result_with("high").grade()[0] == "D"


def test_low_findings_keep_the_plain_sum():
    assert result_with("low", "low").risk_index() == 2


@pytest.mark.parametrize("payload", [{"scan_aborted": "cancelado"}, {"version": {}}])
def test_token_is_never_saved(tmp_path, monkeypatch, payload):
    secret = "SECRETO123"

    def fake_run(_cmd, _timeout):
        (tmp_path / "wpscan.json").write_text(json.dumps(payload))
        return 4, f"--api-token {secret}", "", 1.0

    monkeypatch.setattr(external, "_run", fake_run)
    monkeypatch.setattr(external.shutil, "which", lambda name: f"/bin/{name}")
    result = result_with()
    external.run_wpscan("https://x", secret, result, tmp_path, 60)
    assert secret not in json.dumps(result.tool_runs)
    assert secret not in (tmp_path / "wpscan.stderr.txt").read_text()


def test_home_redirect_outside_scope_stops_without_report(custom_site, tmp_path):
    url = custom_site(lambda _p: (301, {"Location": "https://otro.example/"}, ""))
    assert main([url, *BASE, "-o", str(tmp_path)]) == 2
    assert not list(tmp_path.iterdir())


def test_one_redirecting_path_does_not_stop_later_checks(custom_site, tmp_path):
    def respond(path):
        if path == "/":
            return 200, {"Content-Type": "text/html"}, HOME
        if path == "/phpmyadmin/":
            return 302, {"Location": "https://otro.example/"}, ""
        if path == "/server-status":
            return 200, {"Content-Type": "text/html"}, "Apache Server Status"
        return 404, {}, "no"

    assert main([custom_site(respond), *BASE, "-o", str(tmp_path)]) == 0
    assert "FILE-SERVERSTATUS" in {f["id"] for f in only_report(tmp_path)["findings"]}


def test_server_errors_do_not_become_positive_controls(custom_site, tmp_path):
    def respond(path):
        if path == "/":
            return 200, {"Content-Type": "text/html"}, HOME
        return 503, {}, "ocupado"

    assert main([custom_site(respond), *BASE, "-o", str(tmp_path)]) == 0
    data = only_report(tmp_path)
    assert not [p for p in data["positives"] if "XML-RPC" in p or "enumerar" in p]
    assert data["coverage"]["XML-RPC"]["status"] == "no evaluada"
    assert data["coverage"]["Respuestas del servidor"]["status"] == "parcial"


def test_blocked_xmlrpc_is_a_positive(custom_site, tmp_path):
    def respond(path):
        return (200, {"Content-Type": "text/html"}, HOME) if path == "/" else (403, {}, "no")

    main([custom_site(respond), *BASE, "-o", str(tmp_path)])
    assert any("XML-RPC" in p for p in only_report(tmp_path)["positives"])


def test_api_outage_is_not_reported_as_premium_plugin(fake_wp, tmp_path):
    main([fake_wp, *BASE, "-o", str(tmp_path)])
    data = only_report(tmp_path)
    assert {p["status"] for p in data["meta"]["plugins"]} == {"No verificado"}
    assert data["coverage"]["Versiones (api.wordpress.org)"]["status"] == "no evaluada"


def test_estimated_version_alone_is_low_severity(monkeypatch):
    html = '<a href="/wp-content/plugins/demo/a.js?ver=1.0">x</a><meta name="generator" content="WordPress 6.0">'
    monkeypatch.setattr(checks, "_api_plugin", lambda _s: {"version": "9.0", "last_updated": ""})

    class Stub:
        @staticmethod
        def get(_path, **_kwargs):
            return None

    result = AuditResult("https://x", "x", "2026-01-01T00:00:00")
    ctx = checks.Ctx(Stub(), result)
    ctx.is_wp, ctx.pages["/"] = True, html
    checks.enum_components(ctx)
    assert result.findings[0].id == "WP-COMP-OUTDATED"
    assert result.findings[0].severity == "low"


def test_full_run_detects_the_planted_problems(fake_wp, tmp_path):
    assert main([fake_wp, *BASE, "-o", str(tmp_path)]) == 0
    data = only_report(tmp_path)
    ids = {f["id"] for f in data["findings"]}
    assert {"FILE-WPCONFIG", "FILE-DEBUGLOG", "XMLRPC-ENABLED", "USR-ENUM", "DIR-LISTING", "REG-OPEN"} <= ids
    assert data["grade"] == "F"
    assert data["coverage"]["Vulnerabilidades conocidas (CVE)"]["status"] == "no evaluada"
    folder = next(tmp_path.iterdir())
    assert stat.S_IMODE(folder.stat().st_mode) == 0o700
    html = (folder / "informe_ejecutivo.html").read_text(encoding="utf-8")
    assert "Evaluación parcial" in html
    assert "DB_PASSWORD" not in json.dumps(data)


def test_fail_on_returns_exit_code_three(fake_wp, tmp_path):
    assert main([fake_wp, *BASE, "-o", str(tmp_path), "--fail-on", "critical"]) == 3


def test_compare_lists_resolved_and_new(fake_wp, tmp_path):
    previous = tmp_path / "antes.json"
    previous.write_text(json.dumps({"grade": "D", "risk_index": 30, "findings": [
        {"id": "VIEJO", "title": "Ya corregido"}, {"id": "USR-ENUM", "title": "Usuarios"}]}), encoding="utf-8")
    out = tmp_path / "out"
    main([fake_wp, *BASE, "-o", str(out), "--compare", str(previous)])
    comparison = only_report(out)["meta"]["comparison"]
    assert comparison["resolved"] == ["Ya corregido"]
    assert comparison["persisting"] == 1
    assert comparison["new"]


def test_authorization_is_required_without_terminal(monkeypatch):
    monkeypatch.setattr("sys.stdin", open("/dev/null"))
    with pytest.raises(SystemExit):
        main(["https://x.example", "--profile", "quick"])


def test_report_escapes_hostile_site_data_and_drops_unsafe_links(tmp_path):
    result = AuditResult("https://x", "x", "2026-01-01T00:00:00", client="<script>alert(1)</script>")
    result.add(Finding(id="A", title="<img src=x onerror=alert(1)>", severity="high", category="c", description="d",
                       recommendation="r", evidence=["</pre><script>alert(2)</script>"],
                       references=["javascript:alert(3)", "https://ok.example/"]))
    write_reports(result, tmp_path, want_pdf=False)
    for name in ("informe_ejecutivo.html", "informe_tecnico.html"):
        html = (tmp_path / name).read_text(encoding="utf-8")
        assert "<script>alert" not in html and "<img src=x" not in html
        assert 'javascript:alert' not in html
    assert "https://ok.example/" in (tmp_path / "informe_tecnico.html").read_text(encoding="utf-8")


def test_clean_site_report_renders(tmp_path):
    result = AuditResult("https://x", "x", "2026-01-01T00:00:00")
    result.positive("Control confirmado")
    write_reports(result, tmp_path, want_pdf=False)
    html = (tmp_path / "informe_ejecutivo.html").read_text(encoding="utf-8")
    assert "Control confirmado" in html and "No se identificaron riesgos" in html


def test_readme_version_uses_changelog_when_stable_tag_is_trunk():
    assert checks.readme_version("Stable tag: 2.1\n") == "2.1"
    assert checks.readme_version('Stable tag: "trunk"\n== Changelog ==\n= 4.12.2 =\n') == "4.12.2"
    assert checks.readme_version("Stable tag: trunk\n== Changelog ==\n= 1.9.4.4 - Dec 17th 2019 =\n") == "1.9.4.4"
    assert checks.readme_version("Stable tag: trunk\n") is None


def test_common_plugin_hidden_from_html_is_found_by_its_readme(custom_site, tmp_path):
    def respond(path):
        if path == "/":
            return 200, {}, '<meta name="generator" content="WordPress 6.0"><a href="/wp-content/themes/t/a.css">x</a>'
        if path.startswith("/wp-content/plugins/iwp-client/readme.txt"):
            return 200, {}, "=== InfiniteWP Client ===\nStable tag: trunk\n== Changelog ==\n= 1.9.4.4 =\n"
        return 404, {}, "not found"
    main([custom_site(respond), *BASE, "-o", str(tmp_path)])
    plugins = {p["slug"]: p for p in only_report(tmp_path)["meta"]["plugins"]}
    assert set(plugins) == {"iwp-client"} and plugins["iwp-client"]["version"] == "1.9.4.4"


def test_wpscan_only_plugins_join_the_inventory():
    result = AuditResult("https://x", "x", "2026-01-01T00:00:00")
    result.meta["plugins"] = [{"slug": "a", "status": "Al día"}]
    external.merge_wpscan_plugins(result, {"plugins": {"a": {}, "b": {"version": {"number": "1.0"}}}})
    assert [(p["slug"], p.get("version")) for p in result.meta["plugins"]] == [("a", None), ("b", "1.0")]


def test_sslscan_is_reported_as_skipped_on_http(tmp_path):
    result = AuditResult("http://127.0.0.1", "127.0.0.1", "2026-01-01T00:00:00")
    external.run_external(result, "http://127.0.0.1", ["sslscan"], tmp_path, None, 5, lambda _m: None)
    assert result.tool_runs[0]["status"] == "omitida"


def _stub(folder, name, body):
    path = folder / name
    path.write_text("#!/usr/bin/env bash\n" + body + "\n")
    path.chmod(0o755)


def _run_install(tmp_path, apt_body="exit 0"):
    stubs = tmp_path / "stubs"
    stubs.mkdir()
    log = tmp_path / "apt.log"
    _stub(stubs, "sudo", 'exec "$@"')
    _stub(stubs, "apt", f'echo "$*" >> {log}\n{apt_body}')
    _stub(stubs, "dpkg-query", 'case "$*" in *python3*|*nmap*) printf "install ok installed";; *) exit 1;; esac')
    env = {**os.environ, "PATH": f"{stubs}:{os.environ['PATH']}", "WPAUDIT_HOME": str(tmp_path / "opt"),
           "WPAUDIT_BIN": str(tmp_path / "wpaudit")}
    root = Path(__file__).resolve().parent.parent
    done = subprocess.run(["bash", str(root / "install.sh")], env=env, capture_output=True, text=True)
    return done, log.read_text()


def test_install_only_requests_missing_packages_without_upgrades(tmp_path):
    done, calls = _run_install(tmp_path)
    assert done.returncode == 0, done.stderr
    assert "nmap" not in calls and "python3" not in calls
    assert "install -y --no-upgrade wpscan" in calls


def test_install_finishes_when_an_optional_package_fails(tmp_path):
    done, _calls = _run_install(tmp_path, 'case "$*" in *wpscan*) exit 100;; esac')
    assert done.returncode == 0, done.stderr
    assert "No se pudieron instalar: wpscan" in done.stdout
    assert (tmp_path / "opt" / "wpaudit" / "__init__.py").exists()


@pytest.mark.skipif(sys.version_info < (3, 11), reason="PYTHONSAFEPATH requiere Python 3.11")
def test_installed_command_ignores_a_wpaudit_folder_in_the_current_directory(tmp_path):
    done, _calls = _run_install(tmp_path)
    assert done.returncode == 0, done.stderr
    fake = tmp_path / "cwd" / "wpaudit"
    fake.mkdir(parents=True)
    (fake / "__main__.py").write_text("print('carpeta local')")
    out = subprocess.run([str(tmp_path / "wpaudit"), "--version"], cwd=fake.parent, capture_output=True, text=True).stdout
    assert "carpeta local" not in out and __version__ in out
