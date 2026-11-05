# Cambios

## 1.2.4

- Agrupa por componente las vulnerabilidades conocidas para que el informe se pueda priorizar.
- Sin CVSS, estima la gravedad por el título y lo indica; ya no marca todo como medio.
- Si no se confirma la versión de un componente, sus vulnerabilidades quedan por confirmar y en gravedad baja.

## 1.2.3

- La guía del token funciona en `zsh`, el shell predeterminado de Kali, y en `bash`.
- Un `WPSCAN_API_TOKEN` vacío o rechazado ya no hace abortar a WPScan.
- Omitir SSLScan en un sitio HTTP ya no marca la evaluación como parcial.

## 1.2.2

- `install.sh` solo instala lo que falta y ya no actualiza paquetes del sistema.
- Si falla una herramienta opcional, wpaudit se instala igual y avisa cuál faltó.
- El comando `wpaudit` ignora una carpeta `wpaudit/` en el directorio actual.

## 1.2.1

- Detecta plugins comunes que no aparecen en el HTML público, revisando su `readme.txt`.
- Obtiene la versión desde el changelog cuando `Stable tag` dice `trunk`.
- Agrega al inventario los plugins que solo encontró WPScan.
- Indica que SSLScan se omitió en sitios HTTP.
- Los mensajes recomiendan configurar el token con `WPSCAN_API_TOKEN`.

## 1.2.0

- Informes rediseñados para pantalla, celular y PDF, con modo oscuro, filtros, búsqueda y botón para copiar correcciones.
- Los informes funcionan sin conexión, no cargan recursos externos y descartan enlaces inseguros.
- Guía para que cada persona configure su propio token de WPScan.
- Las plantillas pasan a archivos propios en `wpaudit/templates/`, más fáciles de modificar.

## 1.1.0

### Seguridad
- El token de WPScan ya no puede quedar en `resultados.json` ni en `raw/`, incluso si WPScan aborta.
- La carpeta de cada auditoría se crea solo para su propietario (permisos 700).

### Resultados más confiables
- Un hallazgo crítico siempre da nota F, y uno alto como mínimo nota D.
- Si la portada redirige fuera del dominio, la auditoría se detiene: antes evaluaba una página vacía y entregaba nota.
- Una ruta que redirige fuera del dominio ya no cancela el resto de esa comprobación.
- Un error del servidor o un límite de peticiones ya no cuenta como control de seguridad positivo.
- Una caída de api.wordpress.org ya no marca los plugins como premium o personalizados.
- Una versión estimada ya no basta para reportar severidad alta.

### Nuevo
- Sección de cobertura: los informes indican qué no se pudo evaluar.
- `--compare`: muestra lo corregido, lo nuevo y lo pendiente frente a una auditoría anterior.
- `--fail-on`: permite usar wpaudit en CI (código de salida 3).

### Más simple
- Paquete único, instalable con `pipx`, y ejecución con `python3 -m wpaudit`.
- `--authorized` basta para confirmar la autorización; `--yes` sigue aceptándose, pero ya no se necesita.
- El comando instalado guarda los informes en la carpeta actual y ya funciona sin `sudo` si se ejecuta como root.
