# Cómo funciona Aegis Guard

Aegis Guard es una **vertical slice funcional** de antivirus y cortafuegos local para Windows. No promete protección absoluta: todas las decisiones se toman en el equipo con evidencia verificable, sin servicios remotos ni consultas externas.

La idea central es: **observar → normalizar → enriquecer → decidir → remediar**, sin escaneos continuos.

## Flujo completo

```mermaid
flowchart LR
  A[ETW: proceso, red, DNS, registro] --> N[Normalización y deduplicación]
  B[FileSystemWatcher + canarios] --> N
  N --> E[Enriquecimiento local\nSHA-256, firma, reputación, YARA-lite, heurística]
  E --> D[Decisión determinista local]
  D --> R{Veredicto}
  R -- Allow --> X[Registrar evento]
  R -- Monitor --> Y[Aviso en UI]
  R -- Block --> Z[Regla WFP por app/IP/puerto]
  R -- Quarantine --> Q[AES-GCM + DPAPI\nreversible desde la UI]
```

## 1. Captura de eventos

El servicio (`Aegis.Service`) mantiene:

- **ETW en tiempo real** de los providers de proceso, red, DNS y registro. No se hacen escaneos periódicos de disco.
- **FileSystemWatcher** sobre directorios de interés, filtrando extensiones ejecutables y documentos con macros.
- **Canarios anti-ransomware**: ficheros señuelo cuyo cambio dispara una observación de alta severidad.
- **Snapshot de procesos** como respaldo cuando ETW no está disponible.

Dos detalles aprendidos en pruebas reales:

- Los campos `daddr`/`saddr` de ETW de red llegan como `Int32` **little-endian**. `16777343` es `127.0.0.1`, no `1.0.0.127`. La conversión vive en `Aegis.Core/TelemetryUtils.cs` y tiene pruebas.
- Una conexión establecida genera miles de eventos por minuto. `EventDeduplicator` conserva un único registro por destino cada 10 segundos. En el equipo de desarrollo esto bajó de ~2470 eventos/6 s a ~18 eventos/12 s.

## 2. Enriquecimiento local

Cada observación se enriquece con señales que no salen del equipo:

| Señal | Qué aporta |
| --- | --- |
| SHA-256 | Identidad del fichero y comparación con listas locales. |
| Firma Authenticode | Distingue firmado de confianza, firmado no válido y sin firma. |
| Reputación local | Historial de decisiones de la sesión, en memoria y sin consultas remotas. |
| YARA-lite | Subconjunto de YARA: cadenas, hexadecimal con `??`, `nocase`/`wide` y `severity`. |
| Heurística | Banderas realmente producidas por el monitor: persistencia en registro, modificación de canarios, beacon C2, ejecución desde `%TEMP%` y padre inusual (Office). |

Las banderas que el monitor no produce se ignoran: no puntúan capacidades no implementadas. `Aegis.Core` contiene estas primitivas; `DetectionPipeline` orquesta el flujo. No existe telemetría saliente: las observaciones solo se escriben en `events.jsonl` / `threats.jsonl`.

## 3. Decisión determinista local

`DecisionEngine` usa únicamente la evidencia local. El riesgo es el score de `LocalAssessment` (hash, reglas, firma, reputación, banderas e IP pública), sin ponderaciones externas:

| Veredicto | Umbral por defecto | Acción |
| --- | --- | --- |
| `Allow` | < 25 | Se registra el evento. |
| `Monitor` | ≥ 25 | Aviso en la UI, sin bloqueo. |
| `Block` | ≥ 58 | Regla WFP para la aplicación/IP/puerto. |
| `Quarantine` | ≥ 80 | Fichero cifrado y retirado, reversible. |

Un indicador crítico local en un fichero (hash en lista de denegación o regla crítica) fuerza cuarentena; si la cuarentena está desactivada, degrada a bloqueo en lugar de permitir la amenaza. Las reglas duplicadas se cuentan una sola vez para no inflar el riesgo. Los umbrales se validan para permanecer ordenados por debajo de 100.

En modo aprendizaje las decisiones se registran, pero no se aplican cuarentena ni bloqueo WFP automáticos. Los indicios verificados localmente (hash en lista de denegación o regla EICAR) se siguen aplicando para no desarmar la protección básica.

## 4. Remediación

- **Firewall WFP:** usa COM `HNetCfg.FwPolicy2` para crear reglas con prefijo `AEGIS Guard`, auditables y eliminables. No hay driver de callout: no inspecciona tráfico en tiempo real ni bloquea conexiones anteriores a la regla.
- **Cuarentena:** AES-GCM con clave protegida por DPAPI. El fichero se puede restaurar desde la UI; el purgado definitivo es explícito.
- **Modo aprendizaje:** registra las conexiones nuevas en `/api/firewall/learned` para revisión y omite la remediación automática, salvo indicios verificados.

## 5. Interfaz y API

La UI es una SPA servida por el propio servicio y mostrada en WebView2 (`Aegis.UI`). El token local se genera en `%AEGIS_DATA_DIR%\ui-token` (por defecto `C:\ProgramData\AegisGuard\ui-token`) y se inyecta en la página como `window.AEGIS_TOKEN`; nunca sale de `127.0.0.1`. Todas las rutas `/api` exigen `Bearer` y solo escuchan en `127.0.0.1`; `/healthz` es público y no expone estado.

Los datos mostrados son reales: no hay valores de ejemplo ni controles decorativos.

## 6. Qué no hace

- No sustituye ni desactiva Microsoft Defender, Bitdefender u otros productos de seguridad.
- No tiene driver kernel: sin callbacks de inyección, sin sandbox y sin antimanipulación a nivel kernel.
- Todo se procesa en el equipo: no hay consultas a servidores ni descargas; funciona sin Internet.
- No descarga firmas: las reglas se entregan con el producto y se editan localmente.
- No promete detección absoluta; los umbrales están pendientes de calibrar con datos propios.
- No realiza escaneos completos periódicos.

La medición en reposo de 20 s dio 77,2 MB de RAM media y 0,05 % de CPU media (máximos puntuales: 78,6 MB y 1 %). El procedimiento está en [benchmarks](BENCHMARKS.md).
