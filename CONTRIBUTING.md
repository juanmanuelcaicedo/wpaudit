# Cómo contribuir

```bash
pip install -e .[dev]
ruff check .
pytest
```

## Añadir una comprobación

1. Escribe `def check_xxx(ctx)` en `wpaudit/checks.py` y regístrala en `CHECKS`.
2. Reporta con `ctx.r.add(Finding(...))`, con una recomendación que se pueda aplicar.
3. Registra los controles confirmados con `ctx.r.positive(...)` y lo que no se pudo evaluar con `ctx.r.cover(...)`.
4. Añade una prueba en `tests/` con el caso positivo y uno que evite falsos positivos.

## Reglas del proyecto

- **No intrusivo:** nada de fuerza bruta, explotación, inyección ni cambios en el sitio.
- **Sin falsos positivos:** valida el contenido, no solo el código HTTP.
- **Honesto:** si algo no se pudo comprobar, se declara; nunca cuenta como aprobado.
- **Sin datos reales:** las pruebas usan `tests/fake_wp_server.py`, nunca sitios de terceros.
