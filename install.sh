#!/usr/bin/env bash
# Instala wpaudit en Kali Linux o Debian. Uso: bash install.sh [--minimal]
#   --minimal: solo las dependencias de Python, sin las herramientas externas.
set -euo pipefail

DEST="${WPAUDIT_HOME:-/opt/wpaudit}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

PACKAGES="python3 python3-requests python3-jinja2"
[ "${1:-}" = "--minimal" ] || PACKAGES="$PACKAGES whatweb sslscan wpscan nmap nikto weasyprint"

echo "[+] Instalando dependencias con apt..."
$SUDO apt update
# shellcheck disable=SC2086
$SUDO apt install -y $PACKAGES

echo "[+] Copiando wpaudit en ${DEST}..."
$SUDO mkdir -p "${DEST}"
$SUDO cp -r "${HERE}/wpaudit" "${DEST}/"

$SUDO tee /usr/local/bin/wpaudit >/dev/null <<WRAPPER
#!/usr/bin/env bash
export PYTHONPATH="${DEST}\${PYTHONPATH:+:\$PYTHONPATH}"
exec python3 -m wpaudit "\$@"
WRAPPER
$SUDO chmod 755 /usr/local/bin/wpaudit

echo "[+] Listo. Pruebe: wpaudit --help"
