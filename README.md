# Aegis Guard

Antivirus y cortafuegos local para Windows construido con .NET nativo y WebView2. Toda la detección, la decisión y la remediación se calculan en el propio equipo: **no hay servicios de inferencia, consultas a la nube ni credenciales de API**. El producto funciona sin conexión a Internet.

Repositorio público: `https://github.com/superbrucesecurity/AegisGuard`.

## Cómo funciona

[Guía completa: evento → evidencia → decisión → remediación](docs/COMO-FUNCIONA.md).

En resumen: ETW, watchers y canarios generan observaciones; se normalizan y deduplican; se enriquecen con hash SHA-256, firma, reputación local, YARA-lite y heurística; un motor determinista aplica umbrales y decide `Allow`/`Monitor`/`Block`/`Quarantine`. El riesgo es el score calculado con esa evidencia local, sin ponderaciones externas.

## Estado de la entrega

| Capacidad | Estado | Nota |
| --- | --- | --- |
| Motor local (hash, firma, reglas YARA-lite, reputación, heurística) | Implementado | Análisis incremental y event-driven. |
| Monitorización ETW + watchers + canarios anti-ransomware | Implementado | ETW activo en el equipo de desarrollo. |
| Firewall WFP por aplicación/IP/puerto | Implementado | Vía COM `HNetCfg.FwPolicy2`, sin driver callout. |
| Cuarentena reversible | Implementado | AES-GCM + DPAPI, rutas restringidas. |
| Motor de decisión determinista | Implementado | Allow / Monitor / Block / Quarantine con riesgo y confianza. |
| UI premium WebView2 | Implementado | Dashboard, firewall, amenazas, cuarentena, historial, ajustes, ayuda. |
| Instalador / desinstalador | Implementado | `deploy/install.cmd` → `Setup-Aegis.ps1`, `deploy/finish.cmd`, `deploy/uninstall.cmd`. |
| Pruebas automáticas | 64 casos | `tests/Aegis.Checks`. |

**Límites honestos:** no es una protección absoluta; no incluye driver kernel, detección de inyección por callback de kernel ni sandbox de ejecución. No sustituye ni desactiva Microsoft Defender, Bitdefender u otros productos de seguridad. En una medición real de 20 s en reposo (24 núcleos lógicos, monitorización y WFP activos) el servicio registró 79,9 MB de RAM media y 0,25 % de CPU media, con máximos puntuales de 82,0 MB y 2 %. El método y el JSON generado están en [benchmarks](docs/BENCHMARKS.md). Sin driver, la defensa de red depende de las reglas WFP disponibles. Esta versión no incluye canal de actualización automática de firmas: las reglas se entregan con el producto y funcionan sin Internet.

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

Después, ejecute `finish.cmd` como administrador para restringir ACL, registrar las tareas de inicio de sesión y crear los accesos directos. Se mantiene como paso separado porque algunos productos de seguridad bloquean scripts que combinan elevación, ACL y persistencia en un único archivo. Acepta argumentos opcionales para pruebas aisladas: `finish.cmd [INSTALLDIR] [DATADIR] [TASKPREFIX] [SHORTCUTNAME]`; sin ellos usa las rutas y nombres de producción.

El instalador y el desinstalador aceptan `-InstallDir` y `-DataDir`, por lo que pueden verificarse en una carpeta temporal sin modificar `C:\Program Files` ni `C:\ProgramData`. El desinstalador también admite `-TaskPrefix` y `-ShortcutName` para limpiar despliegues aislados. El ciclo completo (instalar → `finish` → arrancar binarios → desinstalar) se validó en una ruta aislada.

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

La SPA se sirve desde `src/Aegis.Service/wwwroot`. El token local se genera en `%AEGIS_DATA_DIR%\ui-token` y WebView2 lo inyecta como `window.AEGIS_TOKEN`; nunca sale de `127.0.0.1`. No es efímero: vive hasta el siguiente arranque del servicio.

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
