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
| Fecha (UTC) | 2026-11-24T20:28:26Z |
| Duración | 20 s, 20 muestras, sin análisis activo |
| Procesador | 24 núcleos lógicos |
| CPU media / máximo puntual | 0,05 % / 1 % |
| RAM media / máxima | 77,2 MB / 78,6 MB (80 960 512 / 82 444 288 bytes) |
| Estado del servicio | `monitorActive=true`, `etwActive=true`, `firewallActive=true`, `protectionState=learning` |
| Eventos observados en la ventana | 130, sin amenazas ni eventos descartados |

El JSON completo de esa ejecución se generó en `artifacts/benchmark-lote2.json` y no se versiona. La media de CPU que informa el propio servicio desde su arranque fue de 0,21 %, coherente con el muestreo externo.

## Objetivos

| Métrica | Objetivo | Resultado de la medición |
| --- | --- | --- |
| RAM en reposo | < 150 MB | Cumplido (77,2 MB de media) |
| CPU en reposo | < 1 % | Cumplido (0,05 % de media) |

Estas cifras corresponden al servicio en reposo, sin escaneos manuales ni carga de trabajo sintética. No prueban el comportamiento bajo ráfaga de eventos, análisis de ficheros grandes ni instalación con `-SelfContained`. Para comparar cambios, repita el mismo comando con el mismo número de muestras y adjunte el JSON generado; no modifique los umbrales para mejorar las cifras.
