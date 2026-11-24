# Operaciones

## Verificación posterior a la instalación

```powershell
$dataDir = if ($env:AEGIS_DATA_DIR) { $env:AEGIS_DATA_DIR } else { Join-Path $env:ProgramData 'AegisGuard' }
$token = (Get-Content -LiteralPath (Join-Path $dataDir 'ui-token') -Raw).Trim()
$h = @{ Authorization = "Bearer $token" }

Invoke-RestMethod http://127.0.0.1:8787/healthz
Invoke-RestMethod http://127.0.0.1:8787/api/health -Headers $h
Invoke-RestMethod http://127.0.0.1:8787/api/status -Headers $h
```

`healthz` es público y solo confirma que el proceso responde; el resto exige el token local. En `/api/status`, compruebe que `serviceRunning`, `managedByScm`, `serviceName`, `monitorActive`, `etwActive` y `firewallActive` reflejan el estado real del equipo; `protectionState` resume el modo (`protected`, `learning`, `limited` o `degraded`). En una instalación con `finish.cmd`, `managedByScm` debe ser `true` y `serviceName` debe coincidir con `AegisGuardSvc` (o el nombre pasado a `finish.cmd`). `blockedTotal` y `quarantinedTotal` son contadores independientes: el primero no son reglas WFP ni paquetes bloqueados. `coalescedEvents` cuenta duplicados suprimidos por la ventana de coalescencia; no es pérdida de visibilidad y no degrada el estado. Solo `droppedEvents`, `queueSaturated`, `watchersDegraded` o una cola con más de 30 s de antigüedad degradan la protección. `intelStatus` distingue `bundled`, `verified:<versión>` y `rejected:<motivo>`; un paquete rechazado no cambia por sí solo el estado de monitorización, pero deja la inteligencia opcional sin cargar y debe corregirse.

El servicio se registra con `sc.exe create ... start= auto`, `binPath` directo al ejecutable y acciones de recuperación `restart/5000`, `restart/10000`, `restart/30000`. No usa `schtasks /SC ONLOGON`: el inicio no depende de que haya sesión. El evento de arranque y el apagado ordenado se escriben en el registro de eventos de Windows con el proveedor del nombre del servicio. `run-service.cmd` solo se conserva para diagnóstico manual.

El token local persiste entre arranques y se guarda con permisos restringidos a SYSTEM, administradores y usuario del servicio. Si el archivo ya existía con una ACL débil, los permisos se reparan al cargarlo. Si está corrupto se conserva como `ui-token.invalid-*` y se genera uno nuevo; la UI se recarga una sola vez para volver a leerlo. Para invalidarlo deliberadamente, detenga el servicio y elimine `ui-token`.

`PUT /api/settings` aplica `maxEvents` en caliente, sin reiniciar el servicio. El valor se valida antes de persistirse y el historial en memoria se recorta de inmediato.

## Validación aislada del instalador

El ciclo se puede probar sin tocar las rutas de producción:

```powershell
$iso = Join-Path $env:TEMP 'aegis-install-smoke'
.\deploy\install.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard"
.\deploy\finish.cmd "$iso\Program" "$iso\AegisGuard" AegisSmoke "Aegis Smoke" AegisSmokeSvc
# finish.cmd crea e inicia el servicio: comprobar Get-Service, /api/status y eventos.
.\deploy\uninstall.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard" -TaskPrefix AegisSmoke -ServiceName AegisSmokeSvc -Yes
```

El desinstalador detiene y elimina el servicio indicado, elimina tareas heredadas con el prefijo indicado (`AegisSmoke *`), el proveedor de eventos, accesos directos, reglas de firewall `AEGIS Guard*`, canarios y datos aislados. Antes de borrar un canario comprueba que la ruta del manifiesto es un archivo `*.aegis-canary-*.txt` dentro del escritorio, Documentos o Descargas del perfil: un manifiesto manipulado no puede convertir la desinstalación en un borrado arbitrario. `uninstall.ps1` acepta `-TaskPrefix`, `-ServiceName` y `-ShortcutName` para limpiar despliegues con otros nombres. No se definieron variables de entorno secretas: el producto no necesita credenciales.

## Estados de protección

| Estado | Significado |
| --- | --- |
| `protected` | Monitor y firewall activos, sin aprendizaje. |
| `learning` | Monitor y firewall activos, modo aprendizaje; no se bloquea tráfico nuevo. |
| `limited` | Monitor activo pero WFP no disponible. |
| `degraded` | Monitorización o ETW no activos, eventos descartados, watchers caídos, cola saturada o eventos con más de 30 s de antigüedad. La visibilidad no es completa; revisar permisos y carga. |

## Ajustes recomendados

- Mantenga `learningMode` activo unos días en equipos nuevos y revise `/api/firewall/learned`. En este modo no se aplican cuarentena ni bloqueo automáticos, salvo indicios verificados localmente.
- `autoQuarantine` y `autoBlockNetwork` deben permanecer activos solo después de calibrar umbrales con datos propios.
- No baje `blockThreshold` por debajo de 50 sin pruebas de falsos positivos.

## Cuarentena

- Los elementos cifrados se guardan en `%AEGIS_DATA_DIR%\quarantine` (o `C:\ProgramData\AegisGuard\quarantine` si no se define la variable).
- `POST /api/quarantine/{id}/restore` restituye el fichero, registra la acción y retira la regla WFP asociada.
- `DELETE /api/quarantine/{id}` purga la copia; no es reversible y también retira la regla WFP asociada.
- Solo se aceptan rutas absolutas que pasen `PathPolicy.IsQuarantineSafe`; se rechazan raíces, rutas relativas y rutas del propio producto.

## Reglas

- Reglas YARA-lite en `%AEGIS_RULES_DIR%` (o `C:\Program Files\AegisGuard\rules`).
- Lista de hashes y dominios en `threat-intel.json` dentro de ese mismo directorio.
- Sintaxis admitida: cadenas y hexadecimal con `??`, modificadores `nocase`/`wide`, meta `severity`/`description`/`sha256`, condiciones `all/any/N of them` (con listas y paréntesis), `filesize`, `uint16/32()` y `hash.sha256`.
- No hay descarga de firmas. Opcionalmente se puede aplicar un paquete local firmado:
  1. Genere una clave ECDSA P-256 de publicación fuera del equipo destino; guárdela como JSON con `algorithm`, `d`, `x` e `y` en hexadecimal y no la incluya en el producto.
  2. Ejecute `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Build-IntelPackage.ps1 -SigningKeyPath <clave.json> -OutputPath <paquete> -Version <versión>`. El script imprime la huella que debe fijarse como `AEGIS_INTEL_KEY_SHA256`.
  3. Copie el paquete al equipo y configure `AEGIS_INTEL_PACKAGE_DIR` y `AEGIS_INTEL_KEY_SHA256` para el servicio; reinicie `AegisGuardSvc`.
  4. Compruebe `/api/status`: `intelStatus` debe ser `verified:<versión>`, con `intelHashCount` y `yaraRuleCount` mayores que cero. Si aparece `rejected:...`, el servicio no cargó ninguna regla del paquete; revise la huella, la firma y los hashes antes de reintentar. Sin las dos variables, `intelStatus=bundled`.
- El paquete solo se carga desde el directorio indicado y no se descarga de Internet. Un fichero `.yar` adicional colocado en ese directorio no se activa si no figura en el manifiesto.

## Rendimiento

Objetivos y observación histórica en el equipo de desarrollo:

| Métrica | Objetivo | Observado históricamente |
| --- | --- | --- |
| CPU media en reposo | < 1 % | 0,25 % (máximo puntual 2 %) |
| RAM residente del servicio | < 150 MB | 79,9 MB de media (82,0 MB de máximo) |

Medición de 20 s con 24 núcleos lógicos, monitorización y WFP activos, sin escaneos manuales. Se repite con `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Measure-Aegis.ps1 -Seconds 30`; el resultado se guarda en `artifacts/benchmark.json`. El método, el estado del servicio durante la medición y las advertencias están en [benchmarks](BENCHMARKS.md). No se realizan escaneos completos periódicos: el análisis se dispara por evento y se deduplica.

## Respuesta a incidentes

1. Exporte el historial desde la UI (**Historial → Exportar JSON**): recorre todas las páginas de `/api/events?limit=1000&skip=N` y genera un JSON con `exportedAt`, `count` y `events`; la tabla solo muestra 200 eventos por rendimiento. También puede consumir `/api/events` y `/api/threats` (ambos admiten `limit`, `skip` y `severity`; `/api/events` también admite `verdict`).
2. Identifique el `observationId` y revise `decision.reasons`.
3. Restaure desde cuarentena solo tras verificar el fichero fuera del equipo.
4. Si un veredicto fue erróneo, ajuste umbrales o añada una excepción; no desactive el motor globalmente.
