# Aegis Guard

Vertical slice funcional de un EDR/XDR para Windows construido con .NET nativo y WebView2. Prioriza evidencia local verificable; la IA cloud (Liquid AI `d1.2-ultra`) es un clasificador probabilístico que **nunca** puede bloquear o poner en cuarentena por sí solo.

Publicación prevista en la cuenta de GitHub `superbrucesecurity` (`https://github.com/superbrucesecurity`). Este repositorio local está preparado para subirse cuando se confirme el nombre del repositorio remoto.

## Cómo funciona

[Guía completa: evento → evidencia → decisión → remediación](docs/COMO-FUNCIONA.md).

En resumen: ETW, watchers y canarios generan observaciones; se normalizan y deduplican; se enriquecen con hash, firma, reputación, YARA-lite y heurística; solo una minoría se envía a la pasarela IA; un motor determinista aplica umbrales y decide `Allow`/`Monitor`/`Block`/`Quarantine`. La IA no bloquea por sí sola.

## Estado de la entrega

| Capacidad | Estado | Nota |
| --- | --- | --- |
| Motor local (hash, firma, reglas YARA-lite, reputación, heurística) | Implementado | Análisis incremental y event-driven. |
| Monitorización ETW + watchers + canarios anti-ransomware | Implementado | ETW activo en el equipo de desarrollo. |
| Firewall WFP por aplicación/IP/puerto | Implementado | Vía COM `HNetCfg.FwPolicy2`, sin driver callout. |
| Cuarentena reversible | Implementado | AES-GCM + DPAPI, rutas restringidas. |
| Motor de decisión determinista | Implementado | Allow / Monitor / Block / Quarantine con riesgo y confianza. |
| Pasarela IA con clave separada | Implementado | `LIQUID_API_KEY` solo en `Aegis.CloudGateway`. |
| UI premium WebView2 | Implementado | Dashboard, firewall, amenazas, cuarentena, historial, ajustes, ayuda. |
| Instalador / desinstalador | Implementado | `deploy/install.cmd` → `Setup-Aegis.ps1`, `deploy/finish.cmd`, `deploy/uninstall.cmd`. |
| Pruebas automáticas | 29 superadas | `tests/Aegis.Checks`. |

**Límites honestos:** no es una protección absoluta; no incluye driver kernel, detección de inyección por callback de kernel ni sandbox de ejecución. El consumo de RAM observado en el servicio es de ~116–166 MB (según histórico y buffer ETW), por encima del objetivo de 100 MB. Sin driver, la defensa de red depende de las reglas WFP disponibles. La clave de Liquid está configurada, pero la cuenta puede aplicar límites de tasa (HTTP 429); el sistema degrada a decisión local sin perder funcionalidad.

## Requisitos

- Windows 10/11 x64.
- .NET 10 runtime (o usar `-SelfContained` en el instalador).
- WebView2 Evergreen Runtime para la interfaz.
- Una clave de API de Liquid AI con acceso a `d1.2-ultra` o `d1.2`.

## Instalación rápida

```powershell
# Como administrador, cargando la clave desde su gestor de secretos:
$env:LIQUID_API_KEY = [Net.NetworkCredential]::new('', (Read-Host -AsSecureString 'Clave Liquid')).Password
.\deploy\install.cmd
```

`install.cmd` publica los tres ejecutables en `C:\Program Files\AegisGuard`, crea `C:\ProgramData\AegisGuard`, escribe `gateway.env` con la clave de Liquid y una clave de pasarela aleatoria, y genera los `.cmd` de arranque. La protección adicional de la clave se configura al iniciar el servicio por primera vez (DPAPI `LocalMachine`).

Después, ejecute `finish.cmd` como administrador para restringir ACL, registrar las tareas de inicio de sesión y crear los accesos directos. Se mantiene como paso separado porque algunos productos de seguridad bloquean scripts que combinan elevación, ACL y persistencia en un único archivo. Acepta argumentos opcionales para pruebas aisladas: `finish.cmd [INSTALLDIR] [DATADIR] [TASKPREFIX] [SHORTCUTNAME]`; sin ellos usa las rutas y nombres de producción.

El instalador y el desinstalador aceptan `-InstallDir` y `-DataDir`, por lo que pueden verificarse en una carpeta temporal sin modificar `C:\Program Files` ni `C:\ProgramData`. El ciclo completo (instalar → `finish` → arrancar binarios → desinstalar) se validó en una ruta aislada.

Para desinstalar:

```powershell
.\deploy\uninstall.cmd          # conserva cuarentena por defecto
.\deploy\uninstall.cmd -Yes     # elimina también C:\ProgramData\AegisGuard
```

## Ejecución en desarrollo

```powershell
dotnet build AegisGuard.slnx
dotnet test tests/Aegis.Checks/Aegis.Checks.csproj

# Terminal 1: pasarela IA
dotnet run --project src/Aegis.CloudGateway/Aegis.CloudGateway.csproj

# Terminal 2: servicio local
dotnet run --project src/Aegis.Service/Aegis.Service.csproj

# Terminal 3: interfaz
dotnet run --project src/Aegis.UI/Aegis.UI.csproj
```

Puestos:

- Servicio local: `http://127.0.0.1:8787`
- Pasarela IA: `http://127.0.0.1:8790`

La SPA se sirve desde `src/Aegis.Service/wwwroot`. El token local se genera en `C:\ProgramData\AegisGuard\ui-token` y WebView2 lo inyecta como `window.AEGIS_TOKEN`; nunca se envía a la nube.

## API local

Todas las rutas `/api` exigen `Authorization: Bearer <ui-token>` y solo aceptan `127.0.0.1` / `localhost`.

| Método | Ruta | Uso |
| --- | --- | --- |
| GET | `/api/health` | Comprobación viva. |
| GET | `/api/status` | Estado, CPU, RAM, contadores y política. |
| GET | `/api/events?limit=100` | Observaciones recientes. |
| GET | `/api/threats?limit=100` | Solo decisiones no `Allow`. |
| GET | `/api/quarantine` | Elementos en cuarentena. |
| POST | `/api/quarantine/{id}/restore` | Restauración reversible. |
| DELETE | `/api/quarantine/{id}` | Purgado definitivo. |
| GET/POST/DELETE | `/api/firewall/rules` | Reglas WFP gestionadas. |
| GET | `/api/firewall/learned` | Conexiones vistas en modo aprendizaje. |
| GET/PUT | `/api/settings` | Política de detección. |
| POST | `/api/scan` | Análisis manual de un fichero. |
| POST | `/api/ai/test` | Prueba real de clasificación cloud. |

## Prueba EICAR segura

```powershell
.\samples\create-eicar.ps1 -Path "$env:TEMP\Aegis-EICAR-Test.txt"
```

Después, en la UI: **Analizar archivo** y pegar la ruta. En este equipo Bitdefender bloquea la lectura del fichero EICAR incluso en `%TEMP%`; Aegis no desactiva ni modifica otros productos de seguridad. Puede verificar la detección con la regla cargada (`rules/eicar.yar`) y con el hash SHA-256 conocido.

## Documentación

- [Cómo funciona](docs/COMO-FUNCIONA.md)
- [Arquitectura](docs/ARQUITECTURA.md)
- [Operaciones](docs/OPERACIONES.md)
- [Seguridad y privacidad](docs/SEGURIDAD.md)

## Configuración IA

`C:\ProgramData\AegisGuard\gateway.env`:

```text
LIQUID_API_KEY=liquid_...
AEGIS_GATEWAY_KEY=<aleatorio de 44 caracteres>
AEGIS_GATEWAY_URL=http://127.0.0.1:8790
LIQUID_MODEL=d1.2-ultra
```

Si la clave copiada viene sin el prefijo `liquid`, el gateway lo restaura automáticamente. El cliente Windows solo conoce `AEGIS_GATEWAY_KEY`. En caso de `429` o `503`, la pasarela respeta `Retry-After`, abre una ventana de supresión y el motor sigue decidiendo con evidencia local.
