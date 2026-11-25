# Benchmarks

Las cifras de rendimiento se obtienen con un script reproducible; no se estiman ni se copian de otros productos.

## Cómo medir

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Measure-Aegis.ps1 -Seconds 30 -Configuration Release -LaunchUi
```

Aegis Guard 3.1 usa dos canales distintos:

- **HTTP local** (`http://127.0.0.1:<puerto>`, 8787 por defecto o el valor de `AEGIS_HTTP_PORT`): solo publica archivos estáticos y `GET /healthz`, que devuelve el texto `ok`. No existen rutas `/api/*`. El script usa `/healthz` únicamente para saber si el servicio responde y para medir el arranque.
- **Named Pipe local** `aegisguard-<hash>-privileged`: atiende todas las operaciones de datos. El hash son los 8 primeros bytes del SHA-256 del SID del usuario autorizado, en hexadecimal minúsculo (16 caracteres). El SID se lee de `AEGIS_UI_USER_SID`; si no está definido, se usa el SID del proceso actual, igual que hace el instalador. La DACL del canal está restringida a ese SID. No se transportan credenciales ni tokens: el servicio identifica al cliente desde su propio token de Windows.

El script:

1. Comprueba `/healthz` en el puerto configurado (`AEGIS_HTTP_PORT` o 8787). Si devuelve `ok`, reutiliza el servicio ya en ejecución y no inventa su arranque (`startupMeasured=false`). Si no responde, inicia el binario de la configuración indicada (`Release` por defecto) con un `AEGIS_DATA_DIR` aislado, fija `AEGIS_UI_USER_SID` al SID resuelto y añade una raíz de escaneo temporal a `AEGIS_SCAN_ALLOWED_ROOTS`. Solo informa `startupMs` cuando `/healthz` devuelve `ok`.
2. Muestrea cada segundo CPU (dividida entre `[Environment]::ProcessorCount`), `WorkingSet64`, bytes privados, lecturas/escrituras acumuladas del árbol de procesos (`Win32_Process.ReadTransferCount`/`WriteTransferCount`) y número de procesos del servicio.
3. Con `-LaunchUi`, inicia `Aegis.UI.exe` y cuenta sus procesos `msedgewebview2.exe` descendientes y su RAM. Esa memoria se informa por separado: no se suma a la del servicio. Al terminar detiene solo la UI y los WebView2 que creó.
4. Envía `Status` por la Named Pipe antes de la fase de carga para conservar la línea base real de monitorización, ETW, firewall, colas y contadores. No consulta `/api/status`: esa ruta fue retirada en 3.1.
5. Fase de carga (omitible con `-SkipLoad`): crea ficheros sintéticos no ejecutables con señales para el analizador de scripts en un directorio temporal **fuera de `AEGIS_DATA_DIR`** (la política `ScanPath` rechaza el directorio de estado), envía `ScanPath` por la Named Pipe con `{ "operation": "ScanPath", "payload": { "path": "<ruta>" } }` y registra latencia media/p95/máxima, throughput, veredictos y deltas de `eventsTotal`, `threatsTotal`, `droppedEvents` y `coalescedEvents`. Ya no se usa `POST /api/scan`. Los ficheros se borran al terminar.
6. Escribe un JSON en `artifacts/benchmark.json` (directorio ignorado por Git). Si el servicio o la UI los inició el script, los detiene al terminar.

Parámetros adicionales: `-SkipLoad`, `-ScanCount <n>`, `-LargeFileBytes <bytes>`, `-Configuration Debug|Release`, `-DataDir <ruta>` y `-OutputPath <archivo>`. No hay parámetros nuevos para credenciales ni para la tubería: esta se deriva del entorno (`AEGIS_UI_USER_SID`) o del usuario actual. Si `/healthz` responde pero la tubería no está disponible para ese SID, no se inventan latencias: `serviceStatus` queda vacío y los fallos de `ScanPath` se registran en `load.errors`.

## Medición de referencia (histórica, 3.0.x)

> **No comparable con 3.1.** Las cifras de esta sección se obtuvieron con Aegis Guard **3.0.0/3.0.1**, cuando `Status` y `ScanPath` se atendían por HTTP (`/api/status` y `POST /api/scan`). En 3.1 esas rutas están retiradas: los datos viajan por la Named Pipe descrita arriba y `ScanPath` aplica una política de rutas permitidas. Por el cambio de transporte y de alcance, estos números **no son comparables** con una medición de 3.1 hasta que se repita la medición con el script actual. No se han publicado resultados nuevos de 3.1.

| Dato | Valor |
| --- | --- |
| Fecha (UTC) | 2026-11-24T20:44:01Z |
| Duración | 20 s, 20 muestras, sin análisis activo |
| Procesador | 24 núcleos lógicos |
| CPU media / máximo puntual | 0,25 % / 2 % |
| RAM media / máxima | 79,9 MB / 82,0 MB (83 781 427 / 85 983 232 bytes) |
| Estado del servicio | `monitorActive=true`, `etwActive=true`, `firewallActive=true`, `protectionState=learning` |
| Eventos observados en la ventana | 64, sin amenazas ni eventos descartados |

El JSON completo de esa ejecución se generó en `artifacts/benchmark-lote4.json` y no se versiona. El estado se leía entonces por HTTP; la media de CPU que informaba el propio servicio desde su arranque fue de 0,44 %. La medición anterior (lote 2, 2026-11-24T20:28:26Z) dio 0,05 % de CPU media, 77,2 MB de RAM media y 130 eventos; las diferencias están dentro de la variación normal del equipo.

### Control tras Fase 3 (3.0.x, histórico)

| Dato | Valor |
| --- | --- |
| Fecha (UTC) | 2026-11-24T22:20:10Z |
| Duración | 20 s, 20 muestras, sin análisis activo |
| Compilación | Debug (la medición Release se realizó después, en la Fase 6) |
| CPU media / máximo puntual | 0,25 % / 2 % |
| RAM media / máxima | 81,8 MB / 84,6 MB (85 766 963 / 88 723 456 bytes) |
| Estado | `monitorActive=true`, `etwActive=true`, `firewallActive=true`, `droppedEvents=0`, 50 eventos y 50 duplicados coalescionados |

El incremento de RAM respecto a la referencia es de unos 2 MB después de añadir los analizadores de PE, scripts, archivos y macros. Sigue siendo una medición en reposo: no incluye escaneos manuales, descompresiones ni ráfagas.

### Medición Fase 6 (Release, con UI y carga; 3.0.x, histórico)

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
| Carga | 21 peticiones `POST /api/scan` (API HTTP de 3.0.x, retirada en 3.1; en 3.1 serían 21 llamadas IPC `ScanPath`), 0 fallos, 0,646 s |
| Latencia media / p95 / máxima | 29,36 ms / 49,93 ms / 121,65 ms (la máxima corresponde al fichero grande) |
| Throughput | 32,529 escaneos/s secuenciales |
| Veredictos | 20 `Monitor`, 1 `Allow` |
| Colas y pérdida al final de la carga | `criticalQueueDepth=0`, `normalQueueDepth=0`, `oldestQueuedSeconds=0`, `droppedEvents=0` |
| Coalescencia en reposo | 46 eventos duplicados suprimidos; no cuentan como pérdida |

El estado leído antes de la carga (por HTTP en 3.0.x) mostró `eventsTotal=58`, `intelStatus=bundled`, 1 hash y 5 reglas incluidas. Durante la carga, `threatsTotal` aumentó en 26 y `droppedEvents` no cambió. El JSON completo se generó en una ruta temporal y no se versiona; el escritorio, Documentos y Descargas reales no se usaron como entrada. La RAM de WebView2 pertenece a la UI, no al requisito de <150 MB del servicio. Estos valores no se han vuelto a medir en 3.1.

## Objetivos

| Métrica | Objetivo | Resultado medido (Fase 6, Release, 3.0.x; histórico) |
| --- | --- | --- |
| RAM del servicio en reposo | < 150 MB | Cumplido (84,47 MB de media, 87,84 MB de máximo) |
| CPU del servicio en reposo | < 1 % | Cumplido en media (0,3 %); máximo puntual del 3 % |
| Pérdida de eventos | 0 con carga sintética | Cumplido (`droppedEvents=0`, colas a 0) |

Estas cifras corresponden al equipo de desarrollo con 24 núcleos lógicos y a la versión 3.0.x con transporte HTTP. No incluyen un escaneo completo del disco, ráfagas concurrentes ni instalación con `-SelfContained`. No se comparan con otros antivirus: no hay pruebas independientes reproducibles compartidas.

## Cómo repetir la medición en 3.1

1. Compile el binario con `dotnet build -c Release` (o `-c Debug` si usa `-Configuration Debug`).
2. Elija un `AEGIS_DATA_DIR` realmente aislado con `-DataDir <ruta>`; el script crea además una raíz de escaneo temporal distinta para los ficheros sintéticos.
3. Si va a medir un servicio instalado cuyo SID autorizado no sea el del usuario que ejecuta el script, exporte `AEGIS_UI_USER_SID` con ese SID antes de lanzar la medición. El pipe se deriva de ese valor; con otro SID la conexión será rechazada por la DACL.
4. Ejecute el mismo comando de la sección «Cómo medir», con las mismas opciones (`-Seconds`, `-ScanCount`, `-LargeFileBytes`, `-LaunchUi`) para que la comparación sea homogénea.
5. Guarde el JSON generado (`-OutputPath`) junto al resultado; es la única prueba de una medición real. Sustituya las tablas históricas solo cuando exista ese JSON de 3.1, sin reutilizar las cifras de 3.0.x y sin modificar los umbrales para mejorarlas.
