# Modelo de amenazas de Aegis Guard 3.1

Este documento es la base de la auditoría de la rama `dev/v3.1`. Describe qué se
protege, quién puede intentar romperlo, qué se ha corregido y qué sigue siendo
un límite conocido. No es una declaración de seguridad absoluta: cada afirmación
se apoya en código, tests o en una verificación reproducible.

## 1. Alcance y supuestos

- Producto: agente local de Windows 10/11 x64, servicio `AegisGuardSvc`
  (`LocalSystem`) e interfaz WebView2 sin privilegios.
- Versión auditada y publicada: `3.1.0` (tag `v3.1.0`), basada en `3.0.1`
  (`785a160`) con las correcciones de `dev/v3.1` descritas aquí.
- No hay nube, IA, telemetría saliente, claves de API ni decisiones externas.
- No se instala ni se afirma un controlador MiniFilter/WFP callout: no hay WDK,
  altitud oficial, firma de driver ni Driver Verifier. El firewall son reglas
  WFP gestionadas por COM; el KPI cuenta reglas, no paquetes bloqueados.
- No se desactiva Microsoft Defender, Bitdefender ni ningún otro antivirus. Las
  pruebas EICAR informan de bloqueos externos como resultado, nunca como fallo
  propio ni como detección inventada.
- Firma de release: certificado autofirmado `CN=Superbrucesecurity`, huella
  SHA-256 `a3481e2b582a7b9304b1e6f37b2f84809315bc925abb2fcb9d723a33159fe4a0`.
  Sin CA pública, Windows muestra editor desconocido. No hay marca de tiempo
  RFC3161.

## 2. Actores

| Actor | Capacidad inicial | Frontera que debe respetar |
|---|---|---|
| Usuario estándar local | Procesos de integridad media, acceso a su perfil y a la UI | No puede leer `%AEGIS_DATA_DIR%`, ejecutar mutaciones ni usar el motor sobre rutas del sistema |
| Usuario administrador de la sesión | Puede elevar con UAC | Debe ser el SID instalado; un token limitado o una cuenta distinta no autoriza |
| Proceso no interactivo / servicio | Puede abrir pipes y puertos | No pertenece a la sesión interactiva: se rechaza |
| Página web remota | Puede inducir navegación o `fetch` desde el navegador del usuario | No obtiene estado ni operaciones: el middleware exige loopback, mismo origen y `Sec-Fetch-Site: same-origin`; la SPA no usa `fetch` para datos |
| Atacante con acceso al ZIP de release | Puede modificar ficheros y manifiestos | No puede sortear pin de firma, hashes, sello del manifiesto ni re-verificación tras copiar |
| Atacante con privilegios iguales a SYSTEM | Puede recalcular DPAPI, alterar HMAC de canarios y reescribir registros | Fuera de la frontera: sin kernel propio no hay integridad fuerte frente a SYSTEM |

## 3. Activos y flujos de confianza

1. **Instalación/actualización**: ZIP → `Verify-Archive.ps1` → `Verify-Release.ps1`
   → copia en `InstallDir` → re-verificación de la copia → registro SCM.
   Confianza: huella fijada + cadena + sello firmado + hashes + ausencia de
   ficheros no declarados.
2. **Interfaz**: WebView2 fija la navegación al dashboard local, sin DevTools ni
   host objects adicionales. La SPA llama a `window.chrome.webview.hostObjects.aegis`.
3. **Canal de datos**: `AegisBridge` → Named Pipe derivada de
   `AEGIS_UI_USER_SID` → `NativeClientIdentity` (PID, SID, integridad, elevación)
   → `PrivilegedOperationPolicy` → `PrivilegedIpcDispatcher` → servicios reales.
4. **HTTP**: solo `index.html`, estáticos y `/healthz`. Cualquier método distinto
   de GET/HEAD devuelve `405`.
5. **Motor**: `DetectionPipeline` → analizadores → `DecisionEngine` →
   `EventStore`/reputación/cuarentena/firewall. El análisis manual no persiste;
   la monitorización automática sí ejecuta la remediación.
6. **Inteligencia opcional**: paquete local firmado ECDSA P-256, clave fijada por
   `AEGIS_INTEL_KEY_SHA256`. Sin URL ni descarga.
7. **Cuarentena**: AES-256-GCM + DPAPI, doble comprobación de hash, ID único,
   restauración sin sobrescribir.

## 4. Hallazgos y correcciones

Severidad según impacto y facilidad de explotación por un actor del alcance.

### P0 — Superficie HTTP e IPC

| ID | Sev. | Hallazgo y evidencia | Corrección verificable | Estado |
|---|---|---|---|---|
| V1 | Media-alta | `POST /api/scan` permitía a cualquier proceso local pedir a LocalSystem que comprobara y analizara una ruta arbitraria, cruzando la ACL de `%AEGIS_DATA_DIR%` | La API HTTP no registra rutas `/api/*`; `ScanPath` pasó al IPC y aplica `ScanPathPolicy`: raíces permitidas, rechazo de estado/sistema y de reparse points | Corregido; test `ElAnalisisNoAceptaRutasDelEstadoNiDelSistema` y prueba de humo de CI |
| V2 | Media | El servidor IPC era secuencial, sin timeout: una trama parcial bloqueaba las cinco mutaciones | Cuatro bucles de aceptación, cuatro slots, `CancellationTokenSource` de 10 s por conexión, timeouts en lectura/escritura y límite de dos análisis concurrentes | Corregido; test de política y prueba de humo IPC |
| V3 | Media | No se auditaban identidad nula, trama vacía, JSON inválido ni operación desconocida; fallos de escritura se silenciaban | `WriteValidation` al inicio del manejo y en cada rechazo; `ILogger.LogError` si falla el JSONL | Corregido |
| V4 | Media-baja | Sin `AEGIS_UI_USER_SID`, la DACL concedía `ReadWrite` a `InteractiveSid` | `RequireConfiguredAuthorizedSid()` impide arrancar el canal sin SID válido en SCM; la DACL sólo incluye SYSTEM y ese SID | Corregido; tests `LaDaclDelPipeNoConcedeAccesoATodosLosUsuariosInteractivos` y `ElSidDeLaInstalacionEsObligatorio...` |
| V5 | Baja | El archivo de respuesta se creaba con la ACL heredada y se restringía después | Se crea un directorio privado, se le aplica la DACL y después se crea el fichero; `ArgumentList` sustituye a la concatenación y la espera UAC tiene límite | Corregido |
| V6 | Baja | `POST /` y `POST /api/...` devolvían `index.html` con `200` por el fallback | Guarda de método global: sólo GET/HEAD; `405` para todo lo demás | Corregido; prueba de humo de CI |
| V7 | Media | Cualquier administrador elevado podía usar el pipe aunque no fuera el usuario instalado | Comparación del SID del token con `AEGIS_UI_USER_SID` antes de cualquier operación | Corregido; test `UnSidDistintoDelInstaladoNoEstaAutorizado` |

Consecuencia de V7: la elevación con una cuenta administradora **distinta** ya
no está autorizada. Es una decisión deliberada de menor superficie; queda
documentada en `docs/SEGURIDAD.md`.

### P0 — Despliegue y cadena de confianza

| ID | Sev. | Hallazgo | Corrección | Estado |
|---|---|---|---|---|
| D1 | Alta | `Verify-Release.ps1` y `Verify-Archive.ps1` sólo avisaban si faltaba la huella esperada | Exigen pin salvo `-AllowUnpinnedSigner` explícito y validan `requiredSignerThumbprint` | Corregido |
| D2 | Media | `Setup-Aegis.ps1` verificaba antes de copiar, pero no la copia instalada (TOCTOU) | Re-verificación en `InstallDir`; `Rollback.ps1` propaga el interruptor | Corregido |
| D3 | Media | `Package-Release.ps1` creaba el ZIP sin reverificarlo | Llama a `Verify-Archive.ps1` sobre el ZIP recién generado | Corregido |
| D4 | Media | `Check-Ci.ps1` omitía scripts ausentes y no comparaba los `.cmd` ni los textos de licencia | Lista fija de scripts, comparación byte a byte, `licenses/` comparada con la caché NuGet, ausencia de `RELEASE-SIGNATURES.ps1` | Corregido |
| D5 | Baja | `Generate-Sbom.ps1` escribía licencias en el repo | `-LicenseDir` permite generarlas en temporal | Corregido |
| D6 | Media | `README.md` documentaba `install.cmd` sin argumentos aunque el instalador lo rechaza | Uso correcto con `-PackageDir` y `-ExpectedSignerSha256`, o `-AllowUnsigned` explícito; `Check-Ci.ps1` comprueba el bloque | Corregido |
| D7 | Media | `.github/workflows/ci.yml` no ejecutaba guardas en `dev/v3.1` | Añadida la rama, SDK fijo `10.0.404`, `timeout-minutes`, `concurrency` y build Debug+Release | Corregido |

### P1 — Motor y evidencia

| ID | Sev. | Hallazgo | Corrección | Estado |
|---|---|---|---|---|
| E1 | Media | `AnalysisLimits.MaxPeBytes` (1 MiB) estaba declarado pero nunca se aplicaba; `PeInspector` recibía el prefijo de 8 MiB | `PeInspector` limita el prefijo a 1 MiB y añade `PE-ANALYSIS-INCOMPLETE` cuando hay más bytes disponibles | Corregido; test `PePrefixIsCappedAtTheDeclaredLimit` |
| E2 | Media | `IntelPackage.TryVerify` comprobaba firma/manifiesto pero no la huella de clave; el pin se aplicaba fuera, en `Program.cs` | `TryVerify(directory, expectedKeyHash, …)` valida formato del pin y coincidencia con la clave antes de cargar nada; `Program.cs` delega en él | Corregido; test `ConfiguredKeyPinIsEnforcedByThePackageVerifier` |
| E3 | Media | No hay correlación multi-evento real: sólo flags dentro del mismo evento, canarios y reputación por hash | `CorrelationEngine` en memoria con dos reglas acotadas (proceso→red, proceso→persistencia), fire-once, TTL/cotas y evidencia con IDs de observación. Guarda anti-feedback: nunca bloquea por sí sola ni crea indicios verificados | Corregido; 12 tests nuevos |
| E4 | Media | No hay informes reales del analizador completo ni UI conectada a ellos | `ScanReport` proyecta cobertura, hallazgos por analizador y contribuciones ya calculadas; `ScanPath` lo transporta sin nueva operación IPC y la SPA lo renderiza sin `fetch` | Corregido; 3 tests nuevos |
| E5 | Media | `Build-IntelPackage.ps1` lee una clave privada ECDSA desde JSON y `.gitignore` no la cubría | Patrones `*-signing-key.json` y `dev-key.json` en `.gitignore`; guarda en `Check-Ci.ps1` | Corregido |

### Riesgos residuales (no corregibles sin cambiar supuestos)

- **Sin kernel propio**: un proceso con privilegios de SYSTEM puede falsificar
  HMAC de canarios (DPAPI del mismo usuario), borrar auditoría y modificar
  decisiones. No se afirma protección contra SYSTEM.
- **Firewall**: gestionar reglas WFP no equivale a inspeccionar paquetes; no hay
  TLS MITM ni bloqueo retroactivo. `blockedTotal` no es un contador de red.
- **Firma autofirmada**: sin CA pública ni RFC3161, la confianza depende del pin
  administrativo y de la cadena local; si el certificado expira o cambia, el
  paquete deja de verificarse.
- **Licencias**: decisión confirmada: no se modifica `LICENSE` ni
  `EULA-EVALUATION.md`. Apache-2.0 sigue bloqueado hasta tener confirmación
  escrita del titular, procedencia de reglas/fragmentos y una decisión sobre la
  EULA. Ver `docs/P1-LICENCIAS.md`.
- **Actualizador HTTPS del prompt 3.1**: decisión confirmada: se mantiene la
  restricción de "sólo paquetes locales firmados, sin URL ni autoactualización".
  No se implementa descarga ni actualización automática.

## 5. Verificación

- `dotnet build AegisGuard.slnx -c Release`: 0 advertencias, 0 errores.
- `dotnet test AegisGuard.slnx -c Release`: 171/171 pruebas (150 originales, 4
  guardas P0, 1 límite PE, 1 pin de inteligencia, 3 de informe y 12 de
  correlación).
- `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\Check-Ci.ps1`:
  etapa real, humo IPC, rechazo de ruta de estado y `405` HTTP.
- CI: `.github/workflows/ci.yml` ejecuta restauración, build Debug/Release,
  tests y `Check-Ci.ps1` en `main`, `dev/v3.0` y `dev/v3.1`.

Release `v3.1.0`: ZIP `AegisGuard-3.1.0-win-x64.zip` con SHA-256
`20796c3ff5619186ef5769b55acd7cb9c2c4b88ec9baff928ecff504d22e832c`, verificado
por `Verify-Release.ps1` y `Verify-Archive.ps1` con el pin `a3481e2b…59fe4a0`.
`v3.0.1` permanece histórica en `785a160` con sus assets originales.
