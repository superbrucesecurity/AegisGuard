# Benchmarks

Las cifras de rendimiento se obtienen con un script reproducible; no se estiman ni se copian de otros productos.

## Cómo medir

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Measure-Aegis.ps1 -Seconds 30 -Configuration Release -LaunchUi
```

El script:

1. Reutiliza el servicio si ya está escuchando en `127.0.0.1:8787` (o en el puerto de `AEGIS_HTTP_PORT`); si no, inicia el binario de la configuración indicada (`Release` por defecto) con un `AEGIS_DATA_DIR` aislado. Si inicia el proceso, mide el tiempo hasta `/healthz` y solo entonces informa `startupMs`; si lo reutiliza, declara `startupMeasured=false` en lugar de inventar el arranque.
2. Muestrea cada segundo CPU (dividida entre `[Environment]::ProcessorCount`), `WorkingSet64`, bytes privados, lecturas/escrituras acumuladas del árbol de procesos (`Win32_Process.ReadTransferCount`/`WriteTransferCount`) y número de procesos del servicio.
3. Con `-LaunchUi`, inicia `Aegis.UI.exe` y cuenta sus procesos `msedgewebview2.exe` descendientes y su RAM. Esa memoria se informa por separado: no se suma a la del servicio. Al terminar detiene solo la UI y los WebView2 que creó.
4. Consulta `/api/status` antes de la fase de carga para conservar la línea base real de monitorización, ETW, firewall, colas y contadores.
5. Fase de carga (omitible con `-SkipLoad`): crea ficheros sintéticos no ejecutables con señales para el analizador de scripts, envía `POST /api/scan` y registra latencia media/p95/máxima, throughput, veredictos y deltas de `eventsTotal`, `threatsTotal`, `droppedEvents` y `coalescedEvents`. Los ficheros se borran al terminar.
6. Escribe un JSON en `artifacts/benchmark.json` (directorio ignorado por Git). Si el servicio o la UI los inició el script, los detiene al terminar.

Parámetros adicionales: `-SkipLoad`, `-ScanCount <n>`, `-LargeFileBytes <bytes>`, `-Configuration Debug|Release`, `-DataDir <ruta>` y `-OutputPath <archivo>`. Si el servicio no responde, la fase de carga se omite y se indica el motivo; nunca se inventan latencias.

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
| Compilación | Debug (la medición Release se realizó después, en la Fase 6) |
| CPU media / máximo puntual | 0,25 % / 2 % |
| RAM media / máxima | 81,8 MB / 84,6 MB (85 766 963 / 88 723 456 bytes) |
| Estado | `monitorActive=true`, `etwActive=true`, `firewallActive=true`, `droppedEvents=0`, 50 eventos y 50 duplicados coalescionados |

El incremento de RAM respecto a la referencia es de unos 2 MB después de añadir los analizadores de PE, scripts, archivos y macros. Sigue siendo una medición en reposo: no incluye escaneos manuales, descompresiones ni ráfagas.

### Medición Fase 6 (Release, con UI y carga)

Comando ejecutado: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Measure-Aegis.ps1 -Seconds 20 -ScanCount 20 -LargeFileBytes 262144 -Configuration Release -LaunchUi`.

| Dato | Valor |
| --- | --- |
| Fecha (UTC) | 2026-11-24T22:57:58Z |
| Compilación | Release, iniciada por el script |
| Arranque hasta `/healthz` | 1323,1 ms (medido solo porque el script creó el proceso) |
| Reposo | 20 s, 20 muestras, monitorización/WFP/ETW activos, `learning` |
| CPU media / máximo puntual | 0,3 % / 3 % |
| RAM del servicio media / máxima | 84,47 MB / 87,84 MB (88 572 109 / 92 102 656 bytes) |
| E/S del árbol del servicio en reposo | 0,42 KB leídos / 84,93 KB escritos |
| Procesos del árbol del servicio | 2 de media, 2 de máximo |
| UI/WebView2 | `uiLaunched=true`, 6 procesos WebView2, 401 MB de RAM máxima acumulada, medidos aparte |
| Carga | 21 peticiones `POST /api/scan` (20 scripts sintéticos + 1 fichero de 256 KiB), 0 fallos, 0,646 s |
| Latencia media / p95 / máxima | 29,36 ms / 49,93 ms / 121,65 ms (la máxima corresponde al fichero grande) |
| Throughput | 32,529 escaneos/s secuenciales |
| Veredictos | 20 `Monitor`, 1 `Allow` |
| Colas y pérdida al final de la carga | `criticalQueueDepth=0`, `normalQueueDepth=0`, `oldestQueuedSeconds=0`, `droppedEvents=0` |
| Coalescencia en reposo | 46 eventos duplicados suprimidos; no cuentan como pérdida |

El estado leído antes de la carga mostró `eventsTotal=58`, `intelStatus=bundled`, 1 hash y 5 reglas incluidas. Durante la carga, `threatsTotal` aumentó en 26 y `droppedEvents` no cambió. El JSON completo se generó en una ruta temporal y no se versiona; el escritorio, Documentos y Descargas reales no se usaron como entrada. La RAM de WebView2 pertenece a la UI, no al requisito de <150 MB del servicio.

## Objetivos

| Métrica | Objetivo | Resultado medido (Fase 6, Release) |
| --- | --- | --- |
| RAM del servicio en reposo | < 150 MB | Cumplido (84,47 MB de media, 87,84 MB de máximo) |
| CPU del servicio en reposo | < 1 % | Cumplido en media (0,3 %); máximo puntual del 3 % |
| Pérdida de eventos | 0 con carga sintética | Cumplido (`droppedEvents=0`, colas a 0) |

Estas cifras corresponden al equipo de desarrollo con 24 núcleos lógicos. No incluyen un escaneo completo del disco, ráfagas concurrentes ni instalación con `-SelfContained`. No se comparan con otros antivirus: no hay pruebas independientes reproducibles compartidas. Para comparar cambios, repita el mismo comando con el mismo número de muestras y adjunte el JSON generado; no modifique los umbrales para mejorar las cifras.
