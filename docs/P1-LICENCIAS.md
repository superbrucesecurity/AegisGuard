# P1 — Auditoría de licencias previa a una apertura

Este documento registra la evidencia técnica recopilada antes de cualquier cambio de licencia. **No modifica `LICENSE` ni `EULA-EVALUATION.md`**: la decisión jurídica sigue pendiente.

## Evidencia verificada

- Historial (`git log --format='%an <%ae>' | Sort-Object -Unique`): un único autor, `superbrucesecurity <soulmaster.game90@gmail.com>`.
- No hay líneas `Co-authored-by` ni `Signed-off-by` en los mensajes de commit.
- No hay archivos binarios de marca, iconos, fuentes ni imágenes en el repositorio (`*.png`, `*.jpg`, `*.ico`, `*.svg`, `*.ttf`, `*.woff*`).
- `deploy/Generate-Sbom.ps1` regenera un SPDX 2.3 de 50 paquetes y 49 filas de avisos; `deploy/Check-Ci.ps1` compara ese resultado con `SBOM.spdx.json` y `THIRD-PARTY-NOTICES.md` en cada ejecución de CI.
- Licencias declaradas por las dependencias:
  - ejecución: MIT y BSD-3-Clause;
  - pruebas: MIT y Apache-2.0;
  - el texto de WebView2 se conserva en `licenses/`.
- Las reglas `.yar` y `threat-intel.json` son definiciones locales del proyecto. `eicar.yar` usa la cadena pública de prueba EICAR como bytes, con hash declarado; no constituye código de terceros incorporado.
- El producto no descarga dependencias ni inteligencia en tiempo de ejecución: la inteligencia opcional entra solo como paquete local firmado.

## Bloqueos que siguen vigentes

1. Confirmación **escrita** del titular de que todo el código y los archivos de reglas son originales o están libres de derechos de terceros.
2. Revisión de que ningún fragmento fue copiado de proyectos externos con licencias incompatibles con Apache-2.0 (en particular ejemplos de WebView2, YARA o reglas de inteligencia).
3. Decisión explícita sobre si se conserva la EULA de evaluación para binarios firmados o se sustituye por una licencia Apache-2.0 uniforme.
4. Verificación de que la cuenta `superbrucesecurity` es la titular efectiva y no solo la identidad que publica el repositorio.

## Cómo se cerrará

Cuando los cuatro puntos anteriores estén documentados, se sustituirá `LICENSE` por Apache-2.0, se ajustará `EULA-EVALUATION.md` y `THIRD-PARTY-NOTICES.md`, y se ejecutará de nuevo `deploy/Check-Ci.ps1`. Hasta entonces, la licencia pública continúa siendo propietaria/de evaluación y no se publica una release bajo otra condición jurídica.
