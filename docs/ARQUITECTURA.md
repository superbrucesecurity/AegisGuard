# Arquitectura

## Componentes

```
Aegis.UI (WPF + WebView2)
    │  HTTP local + bearer token
    ▼
Aegis.Service (ASP.NET Core, 127.0.0.1:8787)
    ├── MonitoringWorker (ETW, FileSystemWatcher, canarios)
    ├── DetectionPipeline (enriquecimiento → decisión → remediación)
    ├── DecisionEngine + RemediationPolicy (deterministas, 100 % local)
    ├── FileInspector → YaraLite / PeInspector / ScriptInspector / ArchiveInspector / MacroInspector
    ├── ThreatIntel / LocalReputation (reputación persistida con checksum)
    ├── IntelPackage (manifiesto ECDSA-P256 + hashes, opcional y sin red)
    ├── QuarantineManager (AES-GCM + DPAPI)
    ├── FirewallManager (WFP COM)
    ├── EventStore (JSONL)
    └── ApiTokenProvider + LocalFileAcl (ACL restringida)
```

No hay pasarela, cliente de inferencia ni salida HTTPS a servidores externos. El único puerto expuesto es el enlace local de loopback `127.0.0.1:8787`.

En las instalaciones gestionadas, `Aegis.Service.exe` se ejecuta como servicio SCM `AegisGuardSvc` (`start= auto`, recuperación escalonada, proveedor de eventos con el mismo nombre). `UseWindowsService` conecta el ciclo de vida con stop/shutdown; `AegisProfilePaths` traduce el SID del usuario interactivo registrado por el instalador a sus carpetas Desktop/Documentos/Downloads, necesarias porque el perfil de `LocalSystem` no las contiene. Sin ese mapeo los watchers quedan degradados.

## Flujo de una observación

1. **Captura**: ETW de procesos/red/registro/DNS, watchers de archivos y canarios anti-ransomware. `PriorityObservationQueue` deduplica por kind+ruta+PID+destino, aplica coalescencia, prioriza alertas críticas y contabiliza descartes; un watcher en error se marca degradado y se recrea.
2. **Enriquecimiento**: una sola lectura acotada produce hash SHA-256, tamaño, coincidencia EICAR (incluso partida entre lecturas) y un prefijo para los analizadores. Sobre esa copia se aplican firma WinTrust por ruta, YARA-lite, `PeInspector`, `ScriptInspector`, `ArchiveInspector` y `MacroInspector`. Los contenedores se leen en memoria con topes declarados antes de descomprimir; nunca se extraen a disco. `ProcessStarted` conserva PID + tiempo de creación para detectar reutilización antes de atribuir evidencia.
3. **Decisión local**: `LocalAssessment` produce score, evidencias y criticalidad. La reputación se lee de `reputation.json` y se actualiza tras la decisión con corroboración. `DecisionEngine` calcula riesgo, confianza, severidad y veredicto con `risk = local.Score`. Las razones incluyen analizador y evidencia, no solo el nombre de la regla.
4. **Remediación**: la regla WFP por aplicación se resuelve antes de mover el archivo; cuarentena reversible solo para rutas seguras; bloqueo WFP solo con veredicto `Block`/`Quarantine`; modo aprendizaje registra conexiones sin bloquear. `Block` y `Quarantine` se contabilizan por separado.
5. **Persistencia**: observaciones y decisiones en `events.jsonl` / `threats.jsonl`, reputación en `reputation.json` (con suma SHA-256 y escritura atómica), todo bajo `%AEGIS_DATA_DIR%` (por defecto `C:\ProgramData\AegisGuard`). Las reglas se leen de `%AEGIS_RULES_DIR%` (por defecto el directorio `rules` del servicio) o, si se configuran `AEGIS_INTEL_PACKAGE_DIR` y `AEGIS_INTEL_KEY_SHA256`, de un paquete local verificado.

El análisis manual (`POST /api/scan`) sigue este mismo flujo y sí persiste el resultado. La prueba EICAR (`POST /api/selftest/eicar`) reutiliza el enriquecimiento y la decisión, pero no escribe eventos ni aplica remediación: crea una muestra en `%AEGIS_DATA_DIR%\selftest`, la analiza y la elimina. Si otro producto retira el archivo, se informa del bloqueo externo en lugar de fingir un resultado.

## Reglas de decisión

- `risk = local.Score`, limitado a 0–100. No hay señales procedentes de redes neuronales ni de servicios remotos.
- Umbrales por defecto: monitor 25, bloqueo 58, cuarentena 80. `PolicySettings.Validate()` los mantiene ordenados y por debajo de 100.
- Un hash en la lista de denegación o una regla local de severidad `Critical` en un fichero fuerza cuarentena (o bloqueo si la cuarentena está desactivada).
- Reglas con el mismo `RuleId` se agrupan antes de puntuar: una doble notificación (watcher + escáner) no duplica el riesgo.
- La confianza se deriva del número de evidencias locales; no es una probabilidad calibrada de un modelo.
- En modo aprendizaje se conserva la decisión, pero `RemediationPolicy` impide la cuarentena y el bloqueo WFP salvo indicio verificado (hash en lista local o EICAR).
- Las banderas no producidas por el monitor se ignoran: no existen pesos para capacidades no implementadas.

## Firewall

`FirewallManager` usa `HNetCfg.FwPolicy2` para crear reglas de bloqueo por aplicación, dirección remota y puerto. Es firewall de usuario, no un callout de kernel: no inspecciona el tráfico en tiempo real ni puede impedir tráfico previo a la creación de la regla. Las reglas creadas llevan prefijo `AEGIS Guard` para poder auditarse y eliminarse; sus descripciones permiten clasificarlas como automáticas o manuales para `/api/firewall/stats`. El KPI del panel cuenta reglas activas, no paquetes bloqueados. No se realiza inspección TLS.

## Límites conocidos

- Sin driver kernel: no hay detección de inyección de procesos a bajo nivel ni protección antimanipulación de procesos propios más allá de ACL y DPAPI. El HMAC del manifiesto de canarios detecta cambios accidentales, pero un proceso con los mismos privilegios puede recalcularlo.
- ETW depende de que los providers estén habilitados y de los permisos del proceso.
- La medición Fase 3 (Debug, reposo) fue de 81,8 MB de RAM media y 0,25 % de CPU media. La medición Fase 6 (Release, UI y 21 escaneos sintéticos) fue de 84,47 MB de RAM media del servicio, CPU media del 0,3 % y `droppedEvents=0`; WebView2 se midió aparte. Ver [benchmarks](BENCHMARKS.md).
- La reputación se persiste localmente en `reputation.json`, pero no es una lista global ni remota: solo refleja decisiones tomadas en este equipo. Un fichero corrupto se ignora y se reconstruye.
- Los analizadores de comprimidos tienen topes explícitos (64 MiB de archivo, 2048 entradas, 32 MiB por miembro, 128 MiB totales, profundidad 3). No se analizan 7z/RAR. El lector OLE no interpreta streams en mini-FAT y los marca como no verificados.
- El paquete de producto se publica en una etapa firmada con Authenticode, un manifiesto `RELEASE-SIGNATURES.json` y un sello firmado `RELEASE-SIGNATURES.ps1` que protege el manifiesto; `Verify-Release.ps1` exige huella SHA-256 fijada, firma válida, hashes exactos y ausencia de ficheros no declarados antes de instalar. `Package-Release.ps1` agrupa la etapa en un ZIP con un sello firmado que declara su SHA-256; `Verify-Archive.ps1` comprueba ese sello y el contenido interior. `-BackupDir` conserva la versión anterior y `Rollback.ps1` la restaura sin tocar el estado. No hay canal de actualización automática ni descarga de firmas. El mecanismo opcional `deploy/Build-IntelPackage.ps1` produce un paquete local con firma ECDSA P-256; el servicio solo lo carga si la huella de su clave coincide con `AEGIS_INTEL_KEY_SHA256` y todos los hashes del manifiesto validan. `/api/status` informa de `intelStatus`, `intelHashCount` y `yaraRuleCount`.
- Las listas de dominios/IP de `threat-intel.json` se entregan vacías en esta versión: las reglas y el hash EICAR son la base usable de detección.
