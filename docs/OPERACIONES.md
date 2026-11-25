# Operaciones

## Verificación posterior a la instalación

```powershell
Invoke-RestMethod http://127.0.0.1:8787/healthz
Invoke-RestMethod http://127.0.0.1:8787/api/health
Invoke-RestMethod http://127.0.0.1:8787/api/status
```

El puerto por defecto es `8787`. Si se define `AEGIS_HTTP_PORT`, el servicio y la UI usan ese valor de forma coherente; modifique las URLs anteriores en consecuencia.

`healthz` es público y solo confirma que el proceso responde; las rutas `/api` no exigen credenciales porque solo devuelven lecturas y análisis. No hay token local ni cabeceras `Bearer`. En `/api/status`, compruebe que `serviceRunning`, `managedByScm`, `serviceName`, `monitorActive`, `etwActive` y `firewallActive` reflejan el estado real del equipo; `protectionState` resume el modo (`protected`, `learning`, `limited` o `degraded`). En una instalación con `finish.cmd`, `managedByScm` debe ser `true` y `serviceName` debe coincidir con `AegisGuardSvc` (o el nombre pasado a `finish.cmd`). `blockedTotal` y `quarantinedTotal` son contadores independientes: el primero no son reglas WFP ni paquetes bloqueados. `coalescedEvents` cuenta duplicados suprimidos por la ventana de coalescencia; no es pérdida de visibilidad y no degrada el estado. Solo `droppedEvents`, `queueSaturated`, `watchersDegraded` o una cola con más de 30 s de antigüedad degradan la protección. `intelStatus` distingue `bundled`, `verified:<versión>` y `rejected:<motivo>`; un paquete rechazado no cambia por sí solo el estado de monitorización, pero deja la inteligencia opcional sin cargar y debe corregirse.

El servicio se registra con `sc.exe create ... start= auto`, `binPath` directo al ejecutable y acciones de recuperación `restart/5000`, `restart/10000`, `restart/30000`. No usa `schtasks /SC ONLOGON`: el inicio no depende de que haya sesión. El evento de arranque y el apagado ordenado se escriben en el registro de eventos de Windows con el proveedor del nombre del servicio. `run-service.cmd` solo se conserva para diagnóstico manual.

El acceso directo a `%AEGIS_DATA_DIR%` está restringido a SYSTEM, administradores y la cuenta de servicio; la UI interactiva no tiene permisos sobre ese árbol. Al arrancar se reparan las ACL heredadas de instalaciones anteriores, incluidas clave de canarios, configuración, reputación, historial y cuarentena.

Los cambios de política se hacen desde la interfaz: WebView2 llama al objeto `aegis`, se solicita consentimiento UAC si hace falta y la operación `PolicyChange` llega al servicio por Named Pipe. El servicio valida la política, la persiste y aplica `maxEvents` en caliente sin reiniciar. `PUT /api/settings` ya no existe. Todos los intentos, autorizados o rechazados, quedan en `%AEGIS_DATA_DIR%\privileged-audit.jsonl`; revise ese archivo si una operación administrativa falla. Para diagnosticar la elevación, compruebe que la cuenta usada sea administrador real (no un token limitado) y que la sesión sea interactiva.

## Verificación continua

El repositorio ejecuta en GitHub Actions (`windows-latest`, .NET 10): restore, build Release, tests y `deploy/Check-Ci.ps1`. El mismo script se puede ejecutar localmente:

```powershell
dotnet build AegisGuard.slnx -c Release --nologo
dotnet test tests/Aegis.Checks/Aegis.Checks.csproj -c Release --no-build --nologo
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Check-Ci.ps1
```

`Check-Ci.ps1` valida la sintaxis de los scripts de despliegue, regenera y compara SBOM/avisos, crea una etapa sin firmar con `Setup-Aegis.ps1 -StageOnly` y comprueba VERSION, scripts copiados, SPA publicada y ausencia de `ui-token`. Después arranca el servicio desde esa etapa con un directorio de estado aislado, un puerto de loopback libre (`AEGIS_HTTP_PORT`), los sensores desactivados solo en ese proceso (`AEGIS_MONITOR_DISABLED=1`; el motor de análisis sigue siendo el real) y un `TEMP` vacío. Así evita que la actividad del runner se registre como observación y verifica que `POST /api/scan` no crea `events.jsonl`, `threats.jsonl` ni `reputation.json` y no cambia contadores, cuarentena ni reglas. No firma, no instala de forma persistente y no publica nada. La auditoría previa a una posible apertura de licencia está en [P1-LICENCIAS.md](P1-LICENCIAS.md).

## Validación aislada del instalador

El ciclo se puede probar sin tocar las rutas de producción:

```powershell
$iso = Join-Path $env:TEMP 'aegis-install-smoke'
.\deploy\install.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard" -AllowUnsigned
.\deploy\finish.cmd "$iso\Program" "$iso\AegisGuard" AegisSmoke "Aegis Smoke" AegisSmokeSvc
# Opcional: añada [INTELPACKAGEDIR] e [INTELKEYHASH] como argumentos sexto y séptimo
# para registrar un paquete firmado; si se omiten, se usan las variables de entorno.
# finish.cmd crea e inicia el servicio: comprobar Get-Service, /api/status y eventos.
.\deploy\uninstall.cmd -InstallDir "$iso\Program" -DataDir "$iso\AegisGuard" -TaskPrefix AegisSmoke -ServiceName AegisSmokeSvc -Yes
```

En ese laboratorio `-AllowUnsigned` es explícito para no depender de un certificado; en producción se usa la cadena firmada descrita abajo. `install.cmd` solo reenvía argumentos a `Setup-Aegis.ps1`.

El desinstalador detiene y elimina el servicio indicado, elimina tareas heredadas con el prefijo indicado (`AegisSmoke *`), el proveedor de eventos, accesos directos, reglas de firewall `AEGIS Guard*`, canarios y datos aislados. Antes de borrar un canario comprueba que la ruta del manifiesto es un archivo `*.aegis-canary-*.txt` dentro del escritorio, Documentos o Descargas del perfil: un manifiesto manipulado no puede convertir la desinstalación en un borrado arbitrario. `uninstall.ps1` acepta `-TaskPrefix`, `-ServiceName` y `-ShortcutName` para limpiar despliegues con otros nombres. No se definieron variables de entorno secretas: el producto no necesita credenciales.

## Firma, verificación y rollback del paquete

El instalador ya no publica y aplica en un solo paso: primero produce una etapa reproducible, luego se firma con un certificado de firma de código y solo después se aplica. La cadena recomendada es:

```powershell
$signer = '<SHA-256 de 64 hexadecimales del certificado>'

# 1. Publicar en una etapa nueva; no se instala nada.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Setup-Aegis.ps1 -StageOnly `
  -StageDir .\artifacts\release-stage -InstallDir "$env:ProgramFiles\AegisGuard" `
  -DataDir "$env:ProgramData\AegisGuard"

# 2. Firmar en el entorno de publicación, con la clave privada fuera del equipo destino.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Sign-Release.ps1 `
  -TargetDir .\artifacts\release-stage -CertificateThumbprint <huella-SHA1>

# 3. Verificar la etapa antes de distribuirla.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Verify-Release.ps1 `
  -TargetDir .\artifacts\release-stage -ExpectedSignerSha256 $signer

# 4. Instalar exigiendo esa misma huella y conservando la versión anterior.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Setup-Aegis.ps1 `
  -PackageDir .\artifacts\release-stage -ExpectedSignerSha256 $signer `
  -BackupDir D:\AegisGuard-backups\v3.0.0

# 5. Registrar el servicio y crear accesos directos.
.\deploy\finish.cmd
```

`Sign-Release.ps1` firma `.exe`, `.dll` y `.ps1` con Authenticode, calcula SHA-256 de todos los ficheros y escribe `RELEASE-SIGNATURES.json` con el esquema `aegis-release-manifest/1`. Además genera `RELEASE-SIGNATURES.ps1`: un sello firmado con Authenticode que declara el SHA-256 del JSON. Ese sello evita que se modifiquen ficheros sin firma propia (reglas, listas, documentos) reescribiendo el manifiesto. El script imprime la huella SHA-256 del certificado: fíjela como `AEGIS_RELEASE_SIGNER_SHA256` o pásela con `-ExpectedSignerSha256`. `Verify-Release.ps1` comprueba que:

- el manifiesto y `VERSION` coinciden;
- la lista de ficheros es exacta: falta o sobra cualquier fichero y se rechaza;
- cada SHA-256 coincide y las rutas no son absolutas, contienen `..` ni son enlaces/reparse points;
- los ejecutables tienen firma Authenticode `Valid`, encadenan correctamente y usan el certificado fijado;
- el sello Authenticode del manifiesto está firmado por la misma clave y su hash coincide con el JSON;
- los ficheros firmados por terceros conservan la firma declarada, sin exigirles la clave del publicador;
- el recuento declarado de firmados propios, firmados por terceros y datos coincide con el paquete.

`Setup-Aegis.ps1` ejecuta esa verificación **antes** de tocar el directorio de instalación. Si no hay manifiesto, se niega salvo que se indique explícitamente `-AllowUnsigned`; esa opción existe para laboratorio y debe evitarse en producción. La instalación guarda la versión anterior en `-BackupDir` con ACL restringida y, si falla la copia, restaura la instalación previa. El directorio de estado nunca se sustituye: cuarentena, eventos, reputación y configuración sobreviven a la actualización.

Para volver atrás:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Rollback.ps1 `
  -BackupDir D:\AegisGuard-backups\v3.0.0 -ExpectedSignerSha256 $signer -Yes
```

`Rollback.ps1` verifica el backup antes de usarlo (salvo `-SkipVerify`, reservado a despliegues antiguos), detiene el servicio si estaba en marcha, intercambia directorios de forma reversible y reinicia el servicio solo si estaba activo. Si el intercambio falla, devuelve la versión que intentaba sustituir. No modifica `AEGIS_DATA_DIR` ni los canarios. Para conservar datos al desinstalar, use `uninstall.cmd -KeepData`.

Prueba aislada realizada con un certificado autofirmado temporal y el interruptor explícito `-AllowUntrustedTestSigner` (en `Sign-Release.ps1`, `Verify-Release.ps1`, `Setup-Aegis.ps1` y `Rollback.ps1`): 64 ficheros verificados, 6 firmados por la clave de prueba, 21 con firma de terceros y 37 datos; alterar `VERSION` fue rechazado; la instalación y una segunda actualización con `-BackupDir` conservaron el marcador del paquete anterior; el rollback verificó el backup, restauró el marcador y dejó `AEGIS_DATA_DIR` intacto. Ese interruptor existe solo para laboratorio: acepta firmas sin cadena de confianza y no debe usarse en producción. No se creó ni eliminó ningún servicio real ni se modificó la ACL de rutas de producción.

Límites honestos: la firma Authenticode se generó sin marca de tiempo RFC3161, por lo que la validez depende de que el certificado y su cadena sigan siendo válidos en el momento de instalar. El `key pinning` depende de que la huella introducida por el administrador sea la correcta; verifíquela por un canal independiente antes de fijarla. Este mecanismo protege la distribución y el rollback, no convierte al proceso en inmune a un atacante con privilegios administrativos en el equipo. No se desactiva Microsoft Defender, Bitdefender ni ningún otro producto para firmar, instalar o probar.

### Paquete descargable

`deploy/Package-Release.ps1` crea un único artefacto a partir de una etapa ya firmada. Antes de comprimir, ejecuta `Verify-Release.ps1`; si la carpeta no supera la verificación, no genera el ZIP. El resultado es `AegisGuard-<versión>-win-x64.zip`, un `.sha256` informativo y `AegisGuard-<versión>-win-x64.stamp.ps1`. El sello está firmado con Authenticode por el **mismo certificado** que el paquete interior y declara el SHA-256 del ZIP y la huella del firmante. La etapa incluye `deploy\` con `Setup-Aegis.ps1`, `install.cmd`, `finish.cmd`, `Verify-Release.ps1`, `Verify-Archive.ps1`, `uninstall.ps1`, `uninstall.cmd`, `Rollback.ps1` y `rollback.cmd`, para que el ZIP sea autocontenido.

Authenticode no puede firmar un ZIP de forma que Windows lo valide como si fuera un ejecutable; por eso la prueba es el sello independiente, no una supuesta firma directa del ZIP. El `.sha256` es solo una comodidad: puede modificarse, mientras que el sello firmado no.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Package-Release.ps1 `
  -PackageDir .\stage -OutputDir .\dist -CertificateThumbprint <huella-sha1> `
  -ExpectedSignerSha256 $signer
```

Quien descarga el artefacto debe verificarlo antes de instalar. Por defecto, `Verify-Archive.ps1` valida el sello, el SHA-256 del ZIP, extrae el contenido a una carpeta temporal y ejecuta de nuevo `Verify-Release.ps1` con la huella del propio sello:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Verify-Archive.ps1 `
  -OutputDir .\dist -ExpectedSignerSha256 $signer
```

Con `-SkipPackageContents` solo comprueba el sello y el hash del ZIP. `-AllowUntrustedTestSigner` existe únicamente para laboratorio con certificados autofirmados y nunca debe usarse para publicar.

Prueba aislada con certificado autofirmado temporal: se generaron los tres artefactos, `Verify-Archive.ps1` validó el sello, el SHA-256 y los 65 ficheros del paquete interior, y un ZIP modificado fue rechazado por diferencia de hash. No se publicó ese paquete de laboratorio ni se usó un certificado de producción.

## Trazabilidad de la distribución

`deploy/Generate-Sbom.ps1` genera `SBOM.spdx.json` (SPDX 2.3) y `THIRD-PARTY-NOTICES.md` a partir de `dotnet list package --include-transitive --format json` y de los `.nuspec` reales de la caché NuGet. El instalador copia ambos archivos, `LICENSE`, `EULA-EVALUATION.md`, `VERSION` y los textos de licencias de terceros (`licenses/`) al directorio de instalación.

- `Directory.Build.props` es la única fuente del número `3.0.0`: ensamblados, `/api/health`, documentación y el archivo `VERSION` instalado leen ese valor. No hay versiones duplicadas en los scripts.
- `LICENSE` declara el código propietario, con todos los derechos reservados. `EULA-EVALUATION.md` concede una licencia limitada, no transferible y revocable para evaluar el paquete firmado sin fines comerciales; prohíbe distribuirlo, revenderlo, comercializarlo y modificar el código o los binarios sin acuerdo escrito. El código se publica únicamente para transparencia y verificación. Las dependencias conservan sus propias licencias; consulte `THIRD-PARTY-NOTICES.md`.
- Para regenerar el SBOM después de cambiar dependencias: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Generate-Sbom.ps1`. Revise el diff: las entradas `NOASSERTION` requieren revisión manual del paquete.
- `finish.cmd [INSTALLDIR] [DATADIR] [TASKPREFIX] [SHORTCUTNAME] [SERVICENAME] [INTELPACKAGEDIR] [INTELKEYHASH]` acepta opcionalmente el paquete firmado de la Fase 4. Si no se pasan los argumentos, se usan las variables de entorno `AEGIS_INTEL_PACKAGE_DIR` y `AEGIS_INTEL_KEY_SHA256`. `Register-Service.ps1` exige ambas o ninguna y valida el SHA-256 de 64 hexadecimales antes de escribirlas en el entorno del SCM.

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
| CPU media en reposo | < 1 % | 0,3 % (máximo puntual 3 %) en Release |
| RAM residente del servicio | < 150 MB | 84,47 MB de media (87,84 MB de máximo) en Release |
| Pérdida de eventos con carga sintética | 0 | `droppedEvents=0`, colas a 0 tras 21 escaneos |

Medición de 20 s con 24 núcleos lógicos, monitorización y WFP activos, compilación Release, UI y WebView2 ejecutándose y una fase de carga de 21 escaneos sintéticos. Se repite con `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Measure-Aegis.ps1 -Seconds 20 -Configuration Release -LaunchUi`; el resultado se guarda en `artifacts/benchmark.json`. `-SkipLoad` omite la carga y `-ScanCount` ajusta su tamaño. WebView2 se mide aparte y su RAM no se suma a la del servicio. El método, el estado real del servicio y las advertencias están en [benchmarks](BENCHMARKS.md). No se realizan escaneos completos periódicos: el análisis se dispara por evento y se deduplica.

## Respuesta a incidentes

1. Exporte el historial desde la UI (**Historial → Exportar JSON**): recorre todas las páginas de `/api/events?limit=1000&skip=N` y genera un JSON con `exportedAt`, `count` y `events`; la tabla solo muestra 200 eventos por rendimiento. También puede consumir `/api/events` y `/api/threats` (ambos admiten `limit`, `skip` y `severity`; `/api/events` también admite `verdict`).
2. Identifique el `observationId` y revise `decision.reasons`.
3. Restaure desde cuarentena solo tras verificar el fichero fuera del equipo.
4. Si un veredicto fue erróneo, ajuste umbrales o añada una excepción; no desactive el motor globalmente.
