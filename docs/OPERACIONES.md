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

`healthz` es público y solo confirma que el proceso responde; el resto exige el token local. En `/api/status`, compruebe que `serviceRunning`, `monitorActive`, `etwActive` y `firewallActive` reflejan el estado real del equipo; `protectionState` resume el modo (`protected`, `learning`, `limited` o `degraded`).

El token local se genera al arrancar el servicio y se guarda con permisos restringidos a SYSTEM, administradores y usuario instalador. Reinicie el servicio si necesita invalidar una sesión.

## Validación aislada del instalador

El ciclo se puede probar sin tocar las rutas de producción:

```powershell
$iso = Join-Path $env:TEMP 'aegis-install-smoke'
.\deploy\install.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard"
.\deploy\finish.cmd "$iso\Program" "$iso\AegisGuard" AegisSmoke "Aegis Smoke"
# Arrancar run-service.cmd / run-ui.cmd y comprobar /healthz y /api/status.
.\deploy\uninstall.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard" -Yes
```

El desinstalador elimina tareas con el prefijo indicado (`AegisSmoke *`), accesos directos, reglas de firewall `AEGIS Guard*`, canarios y datos aislados. `uninstall.ps1` acepta `-TaskPrefix` y `-ShortcutName` para limpiar despliegues con otros nombres. No se definieron variables de entorno secretas: el producto no necesita credenciales.

## Estados de protección

| Estado | Significado |
| --- | --- |
| `protected` | Monitor y firewall activos, sin aprendizaje. |
| `learning` | Monitor y firewall activos, modo aprendizaje; no se bloquea tráfico nuevo. |
| `limited` | Monitor activo pero WFP no disponible. |
| `degraded` | Monitorización no activa o ETW caído (se usa sondeo de procesos); revisar permisos. |

## Ajustes recomendados

- Mantenga `learningMode` activo unos días en equipos nuevos y revise `/api/firewall/learned`.
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
- No hay descarga de firmas. Si se añade un canal de actualización, debe verificar firma y hash antes de aplicar cambios y no ser necesario para la protección local.

## Rendimiento

Objetivos y observación histórica en el equipo de desarrollo:

| Métrica | Objetivo | Observado históricamente |
| --- | --- | --- |
| CPU media en reposo | < 1 % | ~0,1–0,6 % con deduplicación de red |
| RAM residente del servicio | < 150 MB | ~116–166 MB (sin benchmark actualizado) |

La RAM incluye el runtime de .NET 10, ASP.NET Core, el buffer de ETW y el histórico en memoria (`config.json → maxEvents`). No se realizan escaneos completos periódicos: el análisis se dispara por evento y se deduplica. Las cifras de CPU y RAM son históricas, no una medición de este lote.

## Respuesta a incidentes

1. Exporte el historial desde la UI (**Historial → Exportar JSON**) o consuma `/api/events` y `/api/threats` (ambos admiten `limit`, `skip` y `severity`; `/api/events` también admite `verdict`).
2. Identifique el `observationId` y revise `decision.reasons`.
3. Restaure desde cuarentena solo tras verificar el fichero fuera del equipo.
4. Si un veredicto fue erróneo, ajuste umbrales o añada una excepción; no desactive el motor globalmente.
