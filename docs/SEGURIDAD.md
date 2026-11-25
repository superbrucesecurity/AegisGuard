# Seguridad y privacidad

El modelo de amenazas, con severidades, evidencias y estado de corrección, está en [THREAT-MODEL.md](THREAT-MODEL.md).

## Sin credenciales externas

El producto no usa claves de API, cuentas de usuario ni servicios de inferencia. No existen archivos de credenciales ni variables de entorno secretas. Toda la lógica de detección y decisión se ejecuta en el equipo.

## Superficie HTTP y canal privilegiado

- Ya no existe `ui-token`, `window.AEGIS_TOKEN` ni autenticación `Bearer`. La SPA no posee ninguna credencial que pueda ser leída por código inyectado en la página.
- El servicio HTTP escucha solo en loopback y publica **únicamente** los archivos estáticos de la interfaz y `/healthz` (`ok`, sin estado interno). No hay rutas `/api/*`: ni lecturas, ni análisis, ni mutaciones. Un `POST`, `PUT` o `DELETE` a cualquier ruta devuelve `405`; un `GET` a `/api/status` devuelve el `index.html` estático, nunca datos del producto. El middleware rechaza cualquier `Host` distinto de `127.0.0.1` / `localhost` / `[::1]`, así como cabeceras `Origin` o `Sec-Fetch-Site` que indiquen otro origen.
- Toda la información que muestra la interfaz (estado, eventos, amenazas, cuarentena, firewall, política) y los análisis (`ScanPath`, `SelftestEicar`) se solicitan al objeto nativo `aegis`, que los atiende por una Named Pipe. `ScanPath` calcula la decisión con el motor real sin escribir historial, reputación ni contadores y sin remediar. Sólo acepta ficheros dentro de los directorios permitidos por la instalación (perfil del usuario, temporales y `AEGIS_SCAN_ALLOWED_ROOTS`); rechaza el directorio de estado `%AEGIS_DATA_DIR%`, las rutas del sistema y cualquier `junction`/reparse point.
- Las cinco mutaciones sensibles (reglas de firewall, restauración/purgado de cuarentena y cambio de política) exigen además una elevación UAC real. La Named Pipe tiene una DACL vacía inicial con accesos explícitos sólo para SYSTEM y el SID fijado por el instalador en `AEGIS_UI_USER_SID`: no hay ACE para `InteractiveSid` ni para el grupo de administradores. Si la variable falta o no es un SID válido, el servicio gestionado por SCM no abre el canal. El nombre se deriva de ese SID y no es configurable.
- El servicio identifica al proceso cliente desde el kernel de Windows: `GetNamedPipeClientProcessId`, apertura de su token y lectura de `TokenUser`, `TokenIntegrityLevel` y `TokenElevationType`. Comprueba también pertenencia a Administradores e Interactivo mediante `CheckTokenMembership` sobre una copia de suplantación. El SID leído del token debe coincidir con el de la instalación. El payload no puede declarar ni alterar estos atributos.
- Las lecturas y los análisis se autorizan por SID del usuario instalado, sesión interactiva e integridad media o superior. Las mutaciones exigen elevación completa (`TokenElevationType.Full`), integridad alta y pertenencia a Administradores. Un token limitado, un proceso en segundo plano, un cliente de integridad baja o una cuenta administradora distinta se rechazan.
- Si la UI no está elevada y la operación lo exige, solicita consentimiento UAC relanzándose con `runas`. El SID del pipe se pasa al proceso elevado, pero éste debe pertenecer al mismo usuario: una elevación con otra cuenta no amplía la autorización y falla de forma explícita. La respuesta se escribe en un directorio temporal privado al que se le aplica la DACL antes de crear el fichero; el llamante original sólo obtiene permiso de lectura. Los argumentos se pasan con `ArgumentList`, no por concatenación, y la espera tiene un límite de dos minutos.
- `PrivilegedIpcDispatcher` rechaza reglas `Allow`: solo se crean reglas de bloqueo con prefijo `AEGIS Guard`. No hay forma de conceder tráfico desde la interfaz, la tubería ni HTTP.
- Cada intento se registra en `privileged-audit.jsonl` con PID, SID, integridad, elevación y motivo, incluidos los fallos de identidad, trama vacía, JSON inválido, operación desconocida y timeouts. Si falla la escritura, el error se publica en el registro de eventos. El registro se rota a 2 MiB y conserva ACL restringida.
- Límites: 64 KiB por solicitud, 256 KiB por respuesta, 10 s por conexión IPC (2 min para la elevación UAC), cuatro clientes simultáneos y dos análisis concurrentes. Un cliente que envíe una trama parcial no bloquea a los demás.
- CSP restrictiva (sin `connect-src` a Internet), `X-Frame-Options: DENY`, `nosniff` y `no-referrer`.
- WebView2 sin DevTools, menú contextual, autoguardado de contraseñas, autocompletado ni mensajería web. Se habilita un único host object (`aegis`) y la navegación queda fijada al extremo local compartido por servicio y UI (`http://127.0.0.1:8787`, o el puerto de `AEGIS_HTTP_PORT`).

## Servicio SCM y privilegios

`finish.cmd` registra `AegisGuardSvc` con `sc.exe`, inicio automático sin sesión y acciones de recuperación. El `binPath` apunta directamente a `Aegis.Service.exe`; las rutas de datos/reglas y el SID de la UI se pasan como variables de entorno del servicio en el registro del SCM, no como secretos: no hay claves ni cuentas. `UseWindowsService` atiende los controles de stop/shutdown y drena la cola antes de apagar. El registro de eventos usa el nombre del servicio como proveedor. La ACL del directorio de estado se restringe a SYSTEM, administradores y usuario del servicio: el usuario interactivo **no** tiene acceso directo a configuración, claves, historial ni cuarentena. `LocalFileAcl.RestrictTree` reaplica esa regla al arrancar para corregir ACL heredadas de versiones anteriores.

Bajo `LocalSystem`, el watcher usa `AegisProfilePaths` para vigilar Desktop/Documentos/Downloads del usuario interactivo en lugar del perfil `systemprofile`; si no se puede resolver el SID, la falta de directorios se refleja en el estado real y no se finge cobertura.

## Privacidad de los datos

Las observaciones y decisiones se escriben únicamente en `events.jsonl` y `threats.jsonl` bajo `%AEGIS_DATA_DIR%`, con ACL restringida. El contenido de los ficheros analizados se procesa en memoria para calcular hash, firma, reglas, PE, scripts, archivos y macros; no se envía a ningún servidor ni se extrae a disco. La reputación se persiste en `reputation.json` con suma SHA-256: un fichero alterado o corrupto se descarta sin afectar a la decisión. Es un historial local, no una lista remota. No hay telemetría saliente.

## Verificación de firma

`FileInspector.VerifySignature` usa el ciclo documentado de WinVerifyTrust: `WTD_STATEACTION_VERIFY=1`, y siempre `WTD_STATEACTION_CLOSE=2` con el mismo `hWVTStateData`, incluso si la verificación falla. Se liberan también la estructura nativa y la cadena del archivo. La consulta usa solo caché local de revocación para no depender de Internet.

Los códigos se mapean a estados verificables: `SignedTrusted`, `Unsigned`, `SignedUntrusted`, `ChainNotVerifiable` y `Unknown`. Una firma válida no implica inocuidad y una firma ausente no implica malware; la cadena no verificable por falta de caché es una señal débil, nunca evidencia crítica.

## Análisis estructural y antibomba

- Todas las lecturas están acotadas: hash/EICAR/YARA hasta 512 MiB por fichero, prefijo de 8 MiB para analizadores, archivos hasta 64 MiB, 2048 entradas, 32 MiB por miembro, 128 MiB acumulados y profundidad de anidamiento 3.
- Los tamaños declarados de ZIP/TAR se comprueban **antes** de descomprimir; la descompresión es streaming y se aborta al superar el límite. Nunca se extraen ficheros a disco, evitando path traversal.
- Una firma válida no exime del resto de analizadores; una firma ausente no es malware. Los scripts no se puntúan por "sin firma" porque WinTrust devuelve `NotApplicable` para esa extensión.
- El análisis de PE, scripts, archivos y macros nunca genera por sí solo un indicador **verificado**. Solo EICAR y los hashes de la lista local lo son. La reputación requiere dos decisiones adversarias para considerarse muy baja.
- La correlación temporal es derivada, en memoria y auditable: guarda los IDs de los eventos correlacionados, con cotas de 1024 PIDs, 6 eventos por PID, 10 minutos de TTL y 24 puntos máximos por observación. Nunca crea un indicador verificado ni bloquea por sí sola; si es la única señal, el riesgo se limita a `BlockThreshold - 1` y la confianza a 0,60. El escaneo manual y EICAR no la alimentan.
- Si el fichero cambia entre la lectura inicial y la verificación final se registra `ANALYSIS-CONTENT-CHANGED`; la decisión no se presenta como fiable. La cuarentena vuelve a calcular el hash antes de mover el archivo.
- Los contenedores cifrados o ilegibles y los streams VBA no interpretados se marcan como `UNVERIFIED`, nunca como malware ni como limpios.

## Paquetes de inteligencia firmados

La actualización de inteligencia es manual y opcional. `deploy/Build-IntelPackage.ps1` firma un manifiesto con ECDSA P-256 sobre curva `nistP256` y genera:

- `manifest.json`: versión, fecha y lista `path`/`sha256` de los ficheros incluidos.
- `manifest.sig`: firma Base64 del manifiesto.
- `public-key.json`: coordenadas `x`/`y` y su propio `sha256`.

El servicio exige dos variables para usar el paquete: `AEGIS_INTEL_PACKAGE_DIR` y `AEGIS_INTEL_KEY_SHA256` (SHA-256 de `x || y`). Sin ambas variables ignora el paquete y carga solo las reglas incluidas (`bundled`). Con ellas, rechaza el paquete completo si falla la firma, la huella de la clave, la forma del manifiesto o cualquiera de los hashes; no aplica una carga parcial. `rejected:motivo` se publica en la operación IPC `Status` y la UI lo muestra como inteligencia no íntegra.

La clave privada es material de firma del publicador y no debe copiarse al equipo destino ni versionarse: `.gitignore` excluye `*-signing-key.json` y `dev-key.json`, y `Check-Ci.ps1` verifica esos patrones. La cadena de confianza es la huella fijada por el administrador: un atacante que reemplace el paquete por otro firmado por una clave distinta no puede cargarlo. No hay URLs, descargas ni decisiones remotas. Los streams VBA en mini-FAT y los contenedores cifrados siguen marcándose como no verificados.

## Colas y visibilidad

Las observaciones críticas (canarios, manipulación de manifiesto, C2, reutilización de PID, saturación) usan una cola prioritaria drenada antes que la normal. La coalescencia se aplica después de registrar el primer evento: los duplicados incrementan `coalescedEvents` pero **no** `droppedEvents`, porque no hay pérdida de visibilidad. Solo los descartes reales (cola llena, `DropOldest`, watcher en error) elevan el estado a `degraded`. Si un `FileSystemWatcher` informa de error, se marca degradación, se descarta y se recrea; la pérdida nunca se oculta como protección completa.

## Canarios

Los ficheros señuelo se crean con atributos oculto, sistema y solo lectura, y con ACL restringida a SYSTEM, administradores y usuario del servicio. Su baseline se guarda en `canaries.json` bajo `%AEGIS_DATA_DIR%`, con un HMAC-SHA256 cuya clave **aleatoria de 32 bytes se persiste** en `canary.key` protegida con DPAPI del usuario del servicio; no se deriva de nuevo en cada arranque. El manifiesto lleva versión, clave de versión y firma canonicalizada; una versión anterior, aunque estuviera firmada, se rechaza como downgrade. Si el manifiesto se edita o corrompe se conserva como `canaries.invalid-*.json`, no se usa como baseline y se genera la bandera `canary_manifest_tampered`, puntuada como evidencia crítica local. Los manifiestos heredados sin versión se migran una sola vez. `RotateKey()` permite sustituir la clave y volver a firmar las baselines conservadas.

Este HMAC detecta edición casual o corrupción, **no** resiste a un proceso con los mismos privilegios que puede recalcular la clave DPAPI y volver a firmar: sin controlador en kernel no hay una frontera de integridad fuerte. La protección real sigue siendo la comparación del hash del fichero señuelo frente a la baseline.

## Cuarentena

- Cifrado AES-GCM con nonce aleatorio por elemento.
- Metadatos protegidos con DPAPI `LocalMachine`.
- Validación estricta de ruta antes de cualquier movimiento; nunca se aceptan rutas relativas, raíces ni rutas del producto.
- La restauración comprueba integridad y nunca sobrescribe: si la ruta original vuelve a existir, la operación falla y el elemento permanece en cuarentena.
- El purgado y la restauración retiran las reglas WFP huérfanas asociadas a la amenaza.

## Actualizaciones

El flujo de publicación separa la etapa de la aplicación. `Setup-Aegis.ps1 -StageOnly` publica con `dotnet publish` en una etapa reproducible; `Sign-Release.ps1` aplica Authenticode a `.exe`, `.dll` y `.ps1` y genera `RELEASE-SIGNATURES.json` con todos los SHA-256 y la huella SHA-256 del certificado. También crea `RELEASE-SIGNATURES.ps1`, un sello firmado que declara el SHA-256 del JSON: sin él, un atacante podría reescribir simultáneamente un fichero de datos sin firma y su hash en el manifiesto. `Verify-Release.ps1` exige que la huella coincida con `AEGIS_RELEASE_SIGNER_SHA256` (o `-ExpectedSignerSha256`), que la cadena de confianza sea `Valid`, que el sello y cada hash coincidan, que las firmas de terceros sean las declaradas y que no haya ficheros no declarados ni rutas que escapen del paquete. El instalador verifica antes de tocar el producto y rechaza el paquete si no hay manifiesto salvo `-AllowUnsigned` explícito. Comprueba también que no haya procesos propios en ejecución. El interruptor `-AllowUntrustedTestSigner` solo existe para laboratorios con certificados autofirmados: relaja la cadena, mantiene el pinning y las firmas y advierte que el paquete no es apto para producción. La firma y `EULA-EVALUATION.md` se entregan juntos: la firma identifica al publicador y la licencia limita el uso a evaluación no comercial, sin redistribución, comercialización ni modificación. Un paquete reenviado por un tercero, aunque conserve la firma, no está autorizado. Para distribuir un solo archivo, `Package-Release.ps1` genera un ZIP y un sello Authenticode que declara su SHA-256 y el certificado firmante; `Verify-Archive.ps1` comprueba el sello y vuelve a verificar el paquete interior. No se presenta el ZIP como firmado directamente con Authenticode.

La sustitución guarda la instalación anterior en `-BackupDir`, restringe su ACL y restaura la copia si falla la operación; `Rollback.ps1` verifica el backup antes de revertir, detiene y reanuda el servicio solo cuando estaba activo y no toca `%AEGIS_DATA_DIR%`. No hay canal de actualización automática de firmas ni de componentes en esta versión. Cualquier mecanismo de autoactualización futuro debe verificar firma digital y hash antes de ejecutarse; las actualizaciones de firmas serán opcionales y no serán necesarias para que la protección local siga funcionando. La firma no lleva marca de tiempo RFC3161: expire el certificado o cambie su cadena y el paquete dejará de verificarse. El pinning depende de la huella fijada por el administrador y no sustituye la verificación de la cadena.

## No hacer

- No desactive Microsoft Defender, Bitdefender ni otro producto de seguridad para ejecutar las pruebas EICAR. Si **Ayuda → Ejecutar prueba EICAR** informa de que la muestra fue bloqueada antes del análisis, ese es el resultado: Aegis no la sustituye ni la presenta como detectada por su motor.
- No exponga el puerto HTTP local (8787 por defecto, o `AEGIS_HTTP_PORT`) mediante reglas de firewall de entrada.
- No definir `AEGIS_MONITOR_DISABLED=1` en una instalación real: deja los watchers, ETW y canarios sin iniciar y la operación IPC `Status` informa de `protectionState=degraded`. El estado `limited` se reserva para cuando falta el firewall de Windows. Solo se usa en el proceso aislado de `Check-Ci.ps1` para que la actividad del runner no se cuente como observación del motor.
- No interprete un veredicto `Allow` como garantía de inocuidad: es una decisión con umbrales locales, no una certificación.
