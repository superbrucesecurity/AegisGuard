# Operaciones

## Verificación posterior a la instalación

```powershell
$dataDir = if ($env:AEGIS_DATA_DIR) { $env:AEGIS_DATA_DIR } else { Join-Path $env:ProgramData 'AegisGuard' }
$token = (Get-Content -LiteralPath (Join-Path $dataDir 'ui-token') -Raw).Trim()
$h = @{ Authorization = "Bearer $token" }

Invoke-RestMethod http://127.0.0.1:8787/healthz
Invoke-RestMethod http://127.0.0.1:8787/api/health -Headers $h
Invoke-RestMethod http://127.0.0.1:8787/api/status -Headers $h
Invoke-RestMethod http://127.0.0.1:8787/api/ai/test -Method Post -Headers $h
```

`healthz` es público y solo confirma que el proceso responde; el resto exige el token local. `ai/test` debe devolver `isValid: true`, `choiceLabel` CLEAN/SUSPICIOUS/MALICIOUS y un `model` distinto de `none`. Si aparece `limitado por Liquid`, espere el número de segundos indicado; el motor local sigue activo.

El token local se genera al arrancar el servicio y se guarda con permisos restringidos a SYSTEM, administradores y usuario instalador. Reinicie el servicio si necesita invalidar una sesión.

## Validación aislada del instalador

El ciclo se puede probar sin tocar las rutas de producción:

```powershell
$iso = Join-Path $env:TEMP 'aegis-install-smoke'
# Defina LIQUID_API_KEY en el entorno antes de llamar al instalador;
# no pegue la clave en el historial de PowerShell ni en los scripts.
.\deploy\install.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard"
.\deploy\finish.cmd "$iso\Program" "$iso\AegisGuard" AegisSmoke "Aegis Smoke"
# Arrancar run-gateway.cmd / run-service.cmd y comprobar /healthz y /api/status.
.\deploy\uninstall.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard" -Yes
```

El desinstalador elimina tareas con el prefijo indicado (`AegisSmoke *`), accesos directos, reglas de firewall `AEGIS Guard*`, canarios y datos aislados. `uninstall.ps1` acepta `-TaskPrefix` y `-ShortcutName` para limpiar despliegues con otros nombres.

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
- `POST /api/quarantine/{id}/restore` restituye el fichero y registra la acción.
- `DELETE /api/quarantine/{id}` purga la copia; no es reversible.
- Solo se aceptan rutas absolutas que pasen `PathPolicy.IsQuarantineSafe`; se rechazan raíces, rutas relativas y rutas del propio producto.

## Reglas

- Reglas YARA-lite en `%AEGIS_RULES_DIR%` (o `C:\Program Files\AegisGuard\rules`).
- Lista de hashes y dominios en `threat-intel.json` dentro de ese mismo directorio.
- Sintaxis admitida: cadenas y hexadecimal con `??`, modificadores `nocase`/`wide`, meta `severity`/`description`/`sha256`, condiciones `all/any/N of them` (con listas y paréntesis), `filesize`, `uint16/32()` y `hash.sha256`.

## Rendimiento

Objetivos y observación en el equipo de desarrollo:

| Métrica | Objetivo | Observado |
| --- | --- | --- |
| CPU media en reposo | < 1 % | ~0,1–0,6 % con deduplicación de red |
| RAM residente del servicio | < 100 MB | ~116–166 MB (no cumplido) |
| Latencia IA | — | ~1,1–2,2 s por llamada |

La RAM incluye el runtime de .NET 10, ASP.NET Core, el buffer de ETW y el histórico en memoria (`config.json → maxEvents`). El objetivo de 100 MB no se alcanza en este equipo; se documenta como desviación conocida en lugar de presentarlo como cumplido.

No se realizan escaneos completos periódicos: el análisis se dispara por evento y se deduplica.

## Respuesta a incidentes

1. Exporte el historial desde la UI (**Historial → Exportar JSON**) o consuma `/api/events` y `/api/threats` (ambos admiten `limit`, `skip` y `severity`; `/api/events` también admite `verdict`).
2. Identifique el `observationId` y revise `decision.reasons`.
3. Restaure desde cuarentena solo tras verificar el fichero fuera del equipo.
4. Si un veredicto fue erróneo, ajuste umbrales o añada una excepción; no desactive el motor globalmente.
