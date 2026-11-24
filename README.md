# Aegis Guard

Antivirus y cortafuegos local para Windows construido con .NET nativo y WebView2. Toda la detección, la decisión y la remediación se calculan en el propio equipo: **no hay servicios de inferencia, consultas a la nube ni credenciales de API**. El producto funciona sin conexión a Internet.

Repositorio público: `https://github.com/superbrucesecurity/AegisGuard`.

## Cómo funciona

[Guía completa: evento → evidencia → decisión → remediación](docs/COMO-FUNCIONA.md).

En resumen: ETW, watchers y canarios generan observaciones; se normalizan y deduplican; se enriquecen con hash SHA-256, firma, reputación local, YARA-lite y heurística; un motor determinista aplica umbrales y decide `Allow`/`Monitor`/`Block`/`Quarantine`. El riesgo es el score calculado con esa evidencia local, sin ponderaciones externas.

## Estado de la entrega

| Capacidad | Estado | Nota |
| --- | --- | --- |
| Motor local (hash, firma, YARA-lite, PE, scripts, comprimidos, macros, reputación, heurística) | Implementado | Análisis incremental, event-driven y con topes antibomba. |
| Monitorización ETW + watchers + canarios anti-ransomware | Implementado | ETW activo en el equipo de desarrollo. |
| Firewall WFP por aplicación/IP/puerto | Implementado | Vía COM `HNetCfg.FwPolicy2`, sin driver callout. |
| Cuarentena reversible | Implementado | AES-GCM + DPAPI, rutas restringidas. |
| Motor de decisión determinista | Implementado | Allow / Monitor / Block / Quarantine con riesgo y confianza. |
| UI premium WebView2 | Implementado | Dashboard, firewall, amenazas, cuarentena, historial, ajustes, ayuda. |
| Instalador / desinstalador | Implementado | `deploy/install.cmd` → `Setup-Aegis.ps1`, `deploy/finish.cmd`, `deploy/uninstall.cmd`. |
| Pruebas automáticas | 121 casos | `tests/Aegis.Checks`. |

### `dev/v3.0` · Fase 1 — correcciones críticas verificadas

- **WinTrust:** ciclo completo `WTD_STATEACTION_VERIFY=1` / `WTD_STATEACTION_CLOSE=2`, liberación nativa y mapeo verificable de estados. La cadena no comprobable sin caché de revocación se clasifica como `ChainNotVerifiable` y nunca como malware.
- **Canarios:** clave HMAC aleatoria persistente protegida con DPAPI, manifiesto versionado y firmado, anti-rollback, conservación de evidencia inválida y rotación de clave sin perder baselines.
- **Colas:** prioridad para alertas críticas, coalescencia corregida (el primer evento ya no se descarta), contadores reales de descarte y alerta de pérdida de visibilidad. Los duplicados coalescionados se contabilizan en `coalescedEvents`, no como pérdida; solo los descartes reales degradan el estado mostrado.
- **Token local:** formato validado, recuperación atómica si está corrupto, conservación del archivo inválido y comparación en tiempo constante. La UI recarga una sola vez si el token cambia.
- **Pipeline:** `ProcessStarted` se enriquece con hash/firma/reglas de la imagen y comprueba PID + tiempo de creación; la regla WFP por aplicación se crea antes de mover el archivo a cuarentena.
- **Métricas:** `Block` y `Quarantine` se contabilizan por separado; `MaxEvents` se aplica en caliente; la versión mostrada se lee del ensamblado (`3.0.0`).

Estas correcciones están cubiertas por tests nuevos; el servicio sigue siendo user-mode y no sustituye un driver firmado.

### `dev/v3.0` · Fase 2 — servicio SCM real

- `finish.cmd` ya no crea la tarea `ONLOGON`: registra `AegisGuardSvc` con `sc.exe`, inicio `auto`, reinicios escalonados `5/10/30 s` y `binPath` directo al ejecutable publicado. Las variables de entorno se escriben en el registro del servicio, de modo que el proceso recibe los controles de stop/shutdown del SCM.
- La SPA y los watchers usan el perfil del usuario interactivo registrado por el instalador (`AEGIS_UI_USER_SID`) incluso cuando el proceso se ejecuta como `LocalSystem`; sin esto, Desktop/Documentos/Downloads apuntaban a `systemprofile` y la protección quedaba degradada.
- Logs en el registro de eventos de Windows con el proveedor del nombre del servicio, verificado con entradas reales. La API `/api/status` informa de `serviceName` y `managedByScm`.
- La desinstalación detiene y elimina el servicio, limpia la tarea heredada y elimina el proveedor del registro de eventos. `run-service.cmd` queda únicamente para diagnóstico manual.

Ciclo verificado en ruta aislada: `install.cmd` → `finish.cmd` → servicio `Running`/`Auto` → API `3.0.0` con token → `uninstall.cmd`. El estado final fue `learning` con `monitorActive=true`, `etwActive=true`, `firewallActive=true`, `droppedEvents=0`, `coalescedEvents=5` y 9 entradas reales en el registro de eventos.

La SPA se verificó en navegador contra el servicio instalado, inyectando el token igual que WebView2: muestra `v3.0.0 · motor local`, `Modo aprendizaje`, KPI `Bloqueos / cuarentenas = 0 / 0`, etiquetas `Servicio SCM: sí`, `Sin pérdida de eventos: sí` y el nombre del servicio en el estado del motor. Durante esa comprobación apareció y se corrigió un `ReferenceError` (`TOKEN` en lugar de `token`) que impedía la carga inicial de datos. No hubo errores de página ni respuestas HTTP ≥ 400 en el contexto de la SPA; el capturador de pantalla no se pudo inspeccionar visualmente con este modelo, por lo que la validación se apoyó en DOM y consola.

### `dev/v3.0` · Fase 3 — motor multicapa local

- `FileInspector.InspectAsync` calcula hash/EICAR en una sola lectura acotada y conserva un prefijo para los analizadores. Si el fichero supera 512 MiB se registra `ANALYSIS-TRUNCATED`; no se presenta como limpio. La cuarentena comprueba el tamaño declarado antes de reservar memoria.
- `PeInspector` analiza cabeceras DOS/COFF/Optional y tabla de secciones sobre la copia ya leída: secciones ejecutables y escribibles, punto de entrada no ejecutable, ausencia de importaciones/hardenings y overlay grande. Una cabecera malformada es `Low`/incompleta, nunca malware.
- `ScriptInspector` decodifica UTF-8/UTF-16 y Base64 observable, y correlaciona codificación, evaluación dinámica, ejecución externa, descarga y ofuscación. Una sola señal es `Info`; hacen falta dos o tres señales independientes para `Medium`/`High`. EICAR codificado sí se verifica como crítico.
- `ArchiveInspector` recorre ZIP/JAR, GZIP y TAR en memoria: comprueba tamaños declarados y acumulados antes de descomprimir, limita entradas, ratio, total y profundidad (3), detecta miembros ejecutables y anidamiento, y marca entradas cifradas como no verificadas. No extrae nada a disco.
- `MacroInspector` localiza `vbaProject.bin` en OOXML y streams VBA legibles en contenedores OLE/CFB; exige autoarranque **y** ejecución externa para `High`. El texto visible de un documento no cuenta como evidencia de macro.
- La reputación se persiste en `reputation.json` con suma de verificación; un fichero corrupto se descarta. La primera decisión adversariabaja la reputación a 0,35 y hace falta una segunda observación para 0,1, evitando el bucle de realimentación.
- Las razones de la UI incluyen el analizador y la evidencia (por ejemplo `pe: PE-WRITABLE-EXECUTABLE-SECTION: … [.text (0xE0000020)]`). Tras analizar se recalcula el hash: si el contenido cambió, se añade `ANALYSIS-CONTENT-CHANGED` en lugar de decidir sobre una lectura distinta.
- Verificado con 121 tests automatizados y build Release sin advertencias. En un servicio aislado, `POST /api/scan` sobre un `.ps1` sintético devolvió `Monitor`, riesgo `42`, razón `script: SCRIPT-MULTIPLE-EXECUTION-SIGNALS … [codificación Base64/PowerShell, evaluación dinámica, ejecución externa]` y creó `reputation.json`; `/api/health` devolvió `3.0.0` con `droppedEvents=0`. La autoprueba EICAR informó de bloqueo externo por Bitdefender antes del análisis, resultado que se respeta sin desactivar ese producto; la detección EICAR del motor está cubierta por tests. **Límites:** no hay módulos YARA reales ni `regex`/`xor`, no se analizan 7z/RAR, y el lector OLE no interpreta streams en mini-FAT (se informan como no verificados). Cada analizador sigue siendo user-mode y determinista.

**Límites honestos:** no es una protección absoluta; no incluye driver kernel, detección de inyección por callback de kernel ni sandbox de ejecución. No sustituye ni desactiva Microsoft Defender, Bitdefender u otros productos de seguridad. En una medición de control de 20 s en reposo tras la Fase 3 (24 núcleos lógicos, monitorización y WFP activos, compilación Debug) el servicio registró 81,8 MB de RAM media y 0,25 % de CPU media, con máximos puntuales de 84,6 MB y 2 % y `droppedEvents=0`. El método, la referencia anterior y el JSON generado están en [benchmarks](docs/BENCHMARKS.md); la medición con carga y compilación Release queda para la Fase 6. Sin driver, la defensa de red depende de las reglas WFP disponibles. Esta versión no incluye canal de actualización automática de firmas: las reglas se entregan con el producto y funcionan sin Internet.

## Requisitos

- Windows 10/11 x64.
- .NET 10 runtime (o usar `-SelfContained` en el instalador).
- WebView2 Evergreen Runtime para la interfaz.
- Sin cuenta, clave ni conexión a Internet.

## Instalación rápida

```powershell
.\deploy\install.cmd
```

`install.cmd` publica `Aegis.Service` y `Aegis.UI` en un directorio temporal, comprueba los ejecutables generados y sustituye la instalación anterior mediante una copia de seguridad que se restaura si falla cualquier paso. Sin procesos propios en ejecución, crea `%AEGIS_DATA_DIR%` (por defecto `C:\ProgramData\AegisGuard`) con ACL restringida, copia las reglas y genera los `.cmd` de arranque. Estos `.cmd` exportan `AEGIS_DATA_DIR` y `AEGIS_RULES_DIR` para que los binarios usen exactamente las mismas rutas aisladas. No se escriben credenciales ni se contacta con servidores externos.

Después, ejecute `finish.cmd` como administrador para restringir ACL, registrar el servicio SCM con inicio automático y crear los accesos directos. Se mantiene como paso separado porque algunos productos de seguridad bloquean scripts que combinan elevación, ACL y persistencia en un único archivo. Acepta argumentos opcionales para pruebas aisladas: `finish.cmd [INSTALLDIR] [DATADIR] [TASKPREFIX] [SHORTCUTNAME] [SERVICENAME]`; sin ellos usa `AegisGuardSvc` y el resto de nombres de producción. El servicio no depende de que exista una sesión de usuario.

El instalador y el desinstalador aceptan `-InstallDir` y `-DataDir`, por lo que pueden verificarse en una carpeta temporal sin modificar `C:\Program Files` ni `C:\ProgramData`. El desinstalador también admite `-TaskPrefix`, `-ServiceName` y `-ShortcutName` para limpiar despliegues aislados. El ciclo completo (instalar → `finish` → servicio activo → desinstalar) se validó en una ruta aislada.

Para desinstalar:

```powershell
.\deploy\uninstall.cmd          # conserva cuarentena por defecto
.\deploy\uninstall.cmd -Yes     # elimina también %AEGIS_DATA_DIR% (por defecto C:\ProgramData\AegisGuard)
```

## Ejecución en desarrollo

```powershell
dotnet build AegisGuard.slnx
dotnet test tests/Aegis.Checks/Aegis.Checks.csproj

# Terminal 1: servicio local
dotnet run --project src/Aegis.Service/Aegis.Service.csproj

# Terminal 2: interfaz
dotnet run --project src/Aegis.UI/Aegis.UI.csproj
```

Puesto: servicio local en `http://127.0.0.1:8787`.

La SPA se sirve desde `src/Aegis.Service/wwwroot`. El token local se guarda en `%AEGIS_DATA_DIR%\ui-token` y WebView2 lo inyecta como `window.AEGIS_TOKEN`; nunca sale de `127.0.0.1`. Persiste entre arranques y solo se regenera si falta o está corrupto; en ese caso el archivo inválido se conserva como `ui-token.invalid-*` y la UI se recarga una vez para tomar la nueva credencial.

## API local

Todas las rutas `/api` exigen `Authorization: Bearer <ui-token>` y solo aceptan `127.0.0.1` / `localhost`. `/healthz` es público y solo confirma que el proceso responde.

| Método | Ruta | Uso |
| --- | --- | --- |
| GET | `/healthz` | Comprobación pública (sin estado interno). |
| GET | `/api/health` | Comprobación viva con token. |
| GET | `/api/status` | Estado, CPU, RAM, contadores y política. |
| GET | `/api/events?limit=100&skip=0&severity=High&verdict=Block` | Observaciones recientes con filtros opcionales. |
| GET | `/api/threats?limit=100&skip=0&severity=Critical` | Solo decisiones no `Allow`, con filtros opcionales. |
| GET | `/api/quarantine` | Elementos en cuarentena. |
| POST | `/api/quarantine/{id}/restore` | Restauración reversible. |
| DELETE | `/api/quarantine/{id}` | Purgado definitivo. |
| GET/POST/DELETE | `/api/firewall/rules` | Reglas WFP gestionadas. |
| GET | `/api/firewall/learned` | Conexiones vistas en modo aprendizaje. |
| GET/PUT | `/api/settings` | Política de detección. |
| POST | `/api/scan` | Análisis manual de un fichero. |

## Prueba EICAR segura

```powershell
.\samples\create-eicar.ps1 -Path "$env:TEMP\Aegis-EICAR-Test.txt"
```

También puede usar **Ayuda → Ejecutar prueba EICAR**: el servicio escribe la muestra en su directorio de estado, la analiza con el motor real y la elimina sin guardarla en el historial; el resultado indica si fue detectada o si otro producto la bloqueó antes del análisis. En este equipo Bitdefender bloquea la lectura del fichero EICAR incluso en `%TEMP%`; Aegis no desactiva ni modifica otros productos de seguridad. La detección también se verifica con la regla cargada (`rules/eicar.yar`) y con el hash SHA-256 conocido.

## Documentación

- [Cómo funciona](docs/COMO-FUNCIONA.md)
- [Arquitectura](docs/ARQUITECTURA.md)
- [Operaciones](docs/OPERACIONES.md)
- [Seguridad y privacidad](docs/SEGURIDAD.md)
- [Benchmarks](docs/BENCHMARKS.md)

## Configuración local

`%AEGIS_DATA_DIR%\config.json` contiene la política de detección (umbrales, `autoQuarantine`, `autoBlockNetwork`, `learningMode` y `maxEvents`). Se puede editar desde la UI (**Configuración**) o con `PUT /api/settings`. No contiene secretos. `learningMode` observa y registra las decisiones sin aplicar cuarentena ni bloqueo automático, salvo indicios verificados en el equipo (hash en lista local o regla EICAR).

Las detecciones se basan en los archivos de `%AEGIS_RULES_DIR%` (por defecto `C:\Program Files\AegisGuard\rules`): reglas `*.yar` (YARA-lite), `threat-intel.json` (hashes, dominios y direcciones IP) y `eicar.yar`. El listado distribuido solo contiene el hash EICAR: las listas de dominios y direcciones IP están vacías porque no se inventan indicadores; la API y los tests comprueban que no coinciden con nada. En tiempo de ejecución no se descarga nada. Cualquier actualización futura de firmas deberá ser firmada, verificable y opcional: la protección local no dependerá de ella.
