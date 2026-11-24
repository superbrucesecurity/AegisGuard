# Arquitectura

## Componentes

```
Aegis.UI (WPF + WebView2)
    │  HTTP local + bearer token
    ▼
Aegis.Service (ASP.NET Core, 127.0.0.1:8787)
    ├── MonitoringWorker (ETW, FileSystemWatcher, canarios)
    ├── DetectionPipeline (enriquecimiento → decisión → remediación)
    ├── DecisionEngine (determinista)
    ├── YaraLiteEngine / FileInspector / ThreatIntel
    ├── QuarantineManager (AES-GCM + DPAPI)
    ├── FirewallManager (WFP COM)
    └── EventStore (JSONL)
    │  HTTP local + X-Aegis-Key
    ▼
Aegis.CloudGateway (127.0.0.1:8790)
    │  HTTPS + Bearer LIQUID_API_KEY
    ▼
Liquid AI /decisions/v1/systemone — d1.2-ultra
```

## Flujo de una observación

1. **Captura**: ETW de procesos/red/registro/DNS, watchers de archivos y canarios anti-ransomware. Se deduplica por ruta+kind y se encola con `Channel` acotado.
2. **Enriquecimiento**: hash SHA-256, tamaño, firma WinTrust, coincidencia EICAR, reglas YARA-lite, reputación y listas locales.
3. **Decisión local**: `LocalAssessment` produce score, evidencias y criticalidad. `DecisionEngine` calcula riesgo, confianza, severidad y veredicto.
4. **IA opcional**: solo se envían eventos con score ≥ 20, banderas de comportamiento, análisis manual o cambios de persistencia. Se manda un subconjunto mínimo (prefijo de hash, tipo, bucket de tamaño, firma, reputación, banderas e IDs de regla). Nunca se envía la ruta completa ni el contenido del fichero.
5. **Remediación**: cuarentena reversible solo para rutas seguras; bloqueo WFP solo con veredicto `Block`/`Quarantine`; modo aprendizaje registra conexiones sin bloquear.
6. **Persistencia**: observaciones y decisiones en `events.jsonl` / `threats.jsonl` bajo `%AEGIS_DATA_DIR%` (por defecto `C:\ProgramData\AegisGuard`). Las reglas se leen de `%AEGIS_RULES_DIR%` (por defecto el directorio `rules` del servicio).

## Reglas de decisión

- `risk = local.Score * (1 - AiWeight) + aiSignal * 100 * AiWeight` cuando la IA es válida; si no, `risk = local.Score`.
- Umbrales por defecto: monitor 25, bloqueo 58, cuarentena 80, peso IA 0.3.
- Un indicador crítico local en un fichero fuerza cuarentena (o bloqueo si la cuarentena está desactivada).
- Una IA MALICIOUS sin respaldo local como máximo eleva a `Monitor`; nunca bloquea ni cuarentena.
- Circuit breaker: 3 fallos → 30 s abierto; caché de 15 min por firma de evidencia.

## Firewall

`FirewallManager` usa `HNetCfg.FwPolicy2` para crear reglas de bloqueo por aplicación, dirección remota y puerto. Es firewall de usuario, no un callout de kernel: no inspecciona el tráfico en tiempo real ni puede impedir tráfico previo a la creación de la regla. Las reglas creadas llevan prefijo `AEGIS Guard` para poder auditarse y eliminarse.

## Límites conocidos

- Sin driver kernel: no hay detección de inyección de procesos a bajo nivel ni protección antimanipulación de procesos propios más allá de ACL y DPAPI.
- ETW depende de que los providers estén habilitados y de los permisos del proceso.
- La RAM residente observada (~116–166 MB, según histórico y buffer ETW) supera el objetivo de 100 MB.
- La cuenta de Liquid puede limitar solicitudes por minuto/segundo; el gateway degrada con `Retry-After`.
