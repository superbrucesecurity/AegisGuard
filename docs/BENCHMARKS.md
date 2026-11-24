# Benchmarks

Las cifras de rendimiento se obtienen con un script reproducible; no se estiman ni se copian de otros productos.

## Cómo medir

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Measure-Aegis.ps1 -Seconds 30
```

El script:

1. Reutiliza el servicio si ya está escuchando en `127.0.0.1:8787`; si no, inicia el binario compilado en Debug con un `AEGIS_DATA_DIR` aislado.
2. Espera a `/healthz` y muestrea cada segundo el tiempo de procesador y el `WorkingSet64` del proceso. El porcentaje de CPU se divide entre `[Environment]::ProcessorCount`.
3. Consulta `/api/status` antes de detener el proceso, para registrar el estado real de monitorización, ETW y firewall.
4. Escribe un JSON en `artifacts/benchmark.json` (directorio ignorado por Git). Si el servicio lo inició el script, lo detiene al terminar.

Para especificar otras rutas: `-DataDir <ruta>` y `-OutputPath <archivo>`.

## Medición de referencia

| Dato | Valor |
| --- | --- |
| Fecha (UTC) | 2026-11-24T20:44:01Z |
| Duración | 20 s, 20 muestras, sin análisis activo |
| Procesador | 24 núcleos lógicos |
| CPU media / máximo puntual | 0,25 % / 2 % |
| RAM media / máxima | 79,9 MB / 82,0 MB (83 781 427 / 85 983 232 bytes) |
| Estado del servicio | `monitorActive=true`, `etwActive=true`, `firewallActive=true`, `protectionState=learning` |
| Eventos observados en la ventana | 64, sin amenazas ni eventos descartados |

El JSON completo de esa ejecución se generó en `artifacts/benchmark-lote4.json` y no se versiona. La media de CPU que informa el propio servicio desde su arranque fue de 0,44 %. La medición anterior (lote 2, 2026-11-24T20:28:26Z) dio 0,05 % de CPU media, 77,2 MB de RAM media y 130 eventos; las diferencias están dentro de la variación normal del equipo.

### Control tras Fase 3

| Dato | Valor |
| --- | --- |
| Fecha (UTC) | 2026-11-24T22:20:10Z |
| Duración | 20 s, 20 muestras, sin análisis activo |
| Compilación | Debug (la ampliación a Release se planifica en la Fase 6) |
| CPU media / máximo puntual | 0,25 % / 2 % |
| RAM media / máxima | 81,8 MB / 84,6 MB (85 766 963 / 88 723 456 bytes) |
| Estado | `monitorActive=true`, `etwActive=true`, `firewallActive=true`, `droppedEvents=0`, 50 eventos y 50 duplicados coalescionados |

El incremento de RAM respecto a la referencia es de unos 2 MB después de añadir los analizadores de PE, scripts, archivos y macros. Sigue siendo una medición en reposo: no incluye escaneos manuales, descompresiones ni ráfagas.

## Objetivos

| Métrica | Objetivo | Resultado de la medición |
| --- | --- | --- |
| RAM en reposo | < 150 MB | Cumplido (81,8 MB de media tras Fase 3) |
| CPU en reposo | < 1 % | Cumplido en media (0,25 %); máximo puntual del 2 % |

Estas cifras corresponden al servicio en reposo, sin escaneos manuales ni carga de trabajo sintética. No prueban el comportamiento bajo ráfaga de eventos, análisis de ficheros grandes ni instalación con `-SelfContained`. Para comparar cambios, repita el mismo comando con el mismo número de muestras y adjunte el JSON generado; no modifique los umbrales para mejorar las cifras.
