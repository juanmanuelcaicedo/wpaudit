#!/usr/bin/env bash
# Instala wpaudit en Kali Linux o Debian. Uso: bash install.sh [--minimal]
#   --minimal: solo las dependencias de Python, sin las herramientas externas.
# Solo instala lo que falta: no actualiza los paquetes que ya tienes.
set -euo pipefail

DEST="${WPAUDIT_HOME:-/opt/wpaudit}"
BIN="${WPAUDIT_BIN:-/usr/local/bin/wpaudit}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

REQUIRED="python3 python3-requests python3-jinja2"
OPTIONAL="whatweb sslscan wpscan nmap nikto weasyprint"
[ "${1:-}" != "--minimal" ] || OPTIONAL=""

is_installed() {
    dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "install ok installed"
}

missing_required=""
missing_optional=""
for pkg in $REQUIRED; do is_installed "$pkg" || missing_required="$missing_required $pkg"; done
for pkg in $OPTIONAL; do is_installed "$pkg" || missing_optional="$missing_optional $pkg"; done

if [ -n "$missing_required$missing_optional" ]; then
    echo "[+] Instalando lo que falta:$missing_required$missing_optional"
    $SUDO apt update || echo "[!] apt update falló; se intentará con las listas actuales."
fi
if [ -n "$missing_required" ]; then
    # shellcheck disable=SC2086
    $SUDO apt install -y --no-upgrade $missing_required
fi
failed=""
for pkg in $missing_optional; do
    $SUDO apt install -y --no-upgrade "$pkg" || failed="$failed $pkg"
done

echo "[+] Copiando wpaudit en ${DEST}..."
$SUDO mkdir -p "${DEST}"
$SUDO rm -rf "${DEST}/wpaudit"
$SUDO cp -r "${HERE}/wpaudit" "${DEST}/"

# PYTHONSAFEPATH evita ejecutar una carpeta wpaudit/ que exista en el directorio actual.
$SUDO tee "$BIN" >/dev/null <<WRAPPER
#!/usr/bin/env bash
export PYTHONSAFEPATH=1
export PYTHONPATH="${DEST}\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m wpaudit "\$@"
WRAPPER
$SUDO chmod 755 "$BIN"

if [ -n "$failed" ]; then
    echo "[!] No se pudieron instalar:$failed. wpaudit funcionará sin ellas; reintenta con: sudo apt install$failed"
fi
echo "[+] Listo. Pruebe: wpaudit --version"
