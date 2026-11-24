# Arquitectura

## Componentes

```
Aegis.UI (WPF + WebView2)
    │  HTTP local + bearer token
    ▼
Aegis.Service (ASP.NET Core, 127.0.0.1:8787)
    ├── MonitoringWorker (ETW, FileSystemWatcher, canarios)
    ├── DetectionPipeline (enriquecimiento → decisión → remediación)
    ├── DecisionEngine (determinista, 100 % local)
    ├── YaraLiteEngine / FileInspector / ThreatIntel
    ├── QuarantineManager (AES-GCM + DPAPI)
    ├── FirewallManager (WFP COM)
    └── EventStore (JSONL)
```

No hay pasarela, cliente de inferencia ni salida HTTPS a servidores externos. El único puerto expuesto es el enlace local de loopback `127.0.0.1:8787`.

## Flujo de una observación

1. **Captura**: ETW de procesos/red/registro/DNS, watchers de archivos y canarios anti-ransomware. Se deduplica por ruta+kind y se encola con `Channel` acotado.
2. **Enriquecimiento**: hash SHA-256, tamaño, firma WinTrust, coincidencia EICAR, reglas YARA-lite, reputación y listas locales.
3. **Decisión local**: `LocalAssessment` produce score, evidencias y criticalidad. `DecisionEngine` calcula riesgo, confianza, severidad y veredicto con `risk = local.Score`.
4. **Remediación**: cuarentena reversible solo para rutas seguras; bloqueo WFP solo con veredicto `Block`/`Quarantine`; modo aprendizaje registra conexiones sin bloquear.
5. **Persistencia**: observaciones y decisiones en `events.jsonl` / `threats.jsonl` bajo `%AEGIS_DATA_DIR%` (por defecto `C:\ProgramData\AegisGuard`). Las reglas se leen de `%AEGIS_RULES_DIR%` (por defecto el directorio `rules` del servicio).

## Reglas de decisión

- `risk = local.Score`, limitado a 0–100. No hay señales procedentes de redes neuronales ni de servicios remotos.
- Umbrales por defecto: monitor 25, bloqueo 58, cuarentena 80. `PolicySettings.Validate()` los mantiene ordenados y por debajo de 100.
- Un hash en la lista de denegación o una regla local de severidad `Critical` en un fichero fuerza cuarentena (o bloqueo si la cuarentena está desactivada).
- Reglas con el mismo `RuleId` se agrupan antes de puntuar: una doble notificación (watcher + escáner) no duplica el riesgo.
- La confianza se deriva del número de evidencias locales; no es una probabilidad calibrada de un modelo.

## Firewall

`FirewallManager` usa `HNetCfg.FwPolicy2` para crear reglas de bloqueo por aplicación, dirección remota y puerto. Es firewall de usuario, no un callout de kernel: no inspecciona el tráfico en tiempo real ni puede impedir tráfico previo a la creación de la regla. Las reglas creadas llevan prefijo `AEGIS Guard` para poder auditarse y eliminarse. No se realiza inspección TLS.

## Límites conocidos

- Sin driver kernel: no hay detección de inyección de procesos a bajo nivel ni protección antimanipulación de procesos propios más allá de ACL y DPAPI.
- ETW depende de que los providers estén habilitados y de los permisos del proceso.
- La RAM residente histórica observada (~116–166 MB, según histórico y buffer ETW) no tiene benchmark actualizado; el objetivo es < 150 MB.
- No hay canal de actualización automática de firmas. Cualquier mecanismo futuro debe verificar firma digital y hash, y ser opcional.
- Las listas de dominios/IP de `threat-intel.json` se entregan vacías en esta versión: las reglas y el hash EICAR son la base usable de detección.
