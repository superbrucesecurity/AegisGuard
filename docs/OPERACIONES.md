# Operaciones

## Verificación posterior a la instalación

```powershell
$token = (Get-Content 'C:\ProgramData\AegisGuard\ui-token' -Raw).Trim()
$h = @{ Authorization = "Bearer $token" }

Invoke-RestMethod http://127.0.0.1:8787/api/health -Headers $h
Invoke-RestMethod http://127.0.0.1:8787/api/status -Headers $h
Invoke-RestMethod http://127.0.0.1:8787/api/ai/test -Method Post -Headers $h
```

`ai/test` debe devolver `isValid: true`, `choiceLabel` CLEAN/SUSPICIOUS/MALICIOUS y un `model` distinto de `none`. Si aparece `limitado por Liquid`, espere el número de segundos indicado; el motor local sigue activo.

## Validación aislada del instalador

El ciclo se puede probar sin tocar las rutas de producción:

```powershell
$iso = "$env:TEMP\aegis-install-smoke"
.\deploy\install.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard"
.\deploy\finish.cmd "$iso\Program" "$iso\AegisGuard" AegisSmoke "Aegis Smoke"
# Arrancar los .exe publicados y comprobar /healthz y /api/status
.\deploy\uninstall.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard" -Yes
```

Recuerde eliminar las tareas `AegisSmoke *` y los accesos `Aegis Smoke.lnk` después de la prueba.

## Estados de protección

| Estado | Significado |
| --- | --- |
| `protected` | Monitor y firewall activos, sin aprendizaje. |
| `learning` | Monitor y firewall activos, modo aprendizaje; no se bloquea tráfico nuevo. |
| `limited` | Monitor activo pero WFP no disponible. |
| `degraded` | Monitorización no activa; revisar permisos ETW. |

## Ajustes recomendados

- Mantenga `learningMode` activo unos días en equipos nuevos y revise `/api/firewall/learned`.
- `autoQuarantine` y `autoBlockNetwork` deben permanecer activos solo después de calibrar umbrales con datos propios.
- No baje `blockThreshold` por debajo de 50 sin pruebas de falsos positivos.

## Cuarentena

- Los elementos cifrados se guardan en `C:\ProgramData\AegisGuard\quarantine`.
- `POST /api/quarantine/{id}/restore` restituye el fichero y registra la acción.
- `DELETE /api/quarantine/{id}` purga la copia; no es reversible.
- Solo se aceptan rutas absolutas que pasen `PathPolicy.IsQuarantineSafe`; se rechazan raíces, rutas relativas y rutas del propio producto.

## Reglas

- Reglas YARA-lite en `C:\Program Files\AegisGuard\rules`.
- Lista de hashes y dominios en `rules/threat-intel.json`.
- La sintaxis YARA admitida es un subconjunto: cadenas, hexadecimal con `??`, modificadores `nocase`/`wide`, meta `severity`/`description` y condiciones `all/any of them`.

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

1. Exporte el historial desde la UI (**Historial → Exportar JSON**) o consuma `/api/events` y `/api/threats`.
2. Identifique el `observationId` y revise `decision.reasons`.
3. Restaure desde cuarentena solo tras verificar el fichero fuera del equipo.
4. Si un veredicto fue erróneo, ajuste umbrales o añada una excepción; no desactive el motor globalmente.
