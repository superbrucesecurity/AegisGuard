# Seguridad y privacidad

## Sin credenciales externas

El producto no usa claves de API, cuentas de usuario ni servicios de inferencia. No existen archivos de credenciales ni variables de entorno secretas. Toda la lógica de detección y decisión se ejecuta en el equipo.

## Token local y protección de la API

- La UI recibe el token del archivo `ui-token`, inyectado por WebView2 en la página cargada.
- El token local **no es efímero**: se conserva entre arranques. Solo se sustituye si falta, está truncado o no es Base64 de 32 bytes; el contenido inválido se copia a `ui-token.invalid-*` antes de sobrescribir el archivo de forma atómica.
- El archivo `ui-token` se crea con ACL que solo concede acceso a SYSTEM, administradores y el usuario del servicio. Si ya existía con permisos débiles, se repara automáticamente al cargarlo.
- Escucha solo en loopback.
- Middleware rechaza cualquier `Host` distinto de `127.0.0.1` / `localhost` / `[::1]`.
- Authorization Bearer obligatoria para `/api`, comparada en tiempo constante sobre el hash de la cabecera y del token (sin filtrar longitud).
- Si el servicio regenera el token mientras la UI está abierta, la SPA recarga una sola vez para que WebView2 vuelva a inyectarlo; un segundo `401` se informa sin bucle.
- CSP restrictiva, `X-Frame-Options: DENY`, `nosniff` y `no-referrer`.
- WebView2 sin DevTools, menú contextual, autoguardado de contraseñas, autocompletado, host objects ni mensajería web.

## Privacidad de los datos

Las observaciones y decisiones se escriben únicamente en `events.jsonl` y `threats.jsonl` bajo `%AEGIS_DATA_DIR%`, con ACL restringida. El contenido de los ficheros analizados se procesa en memoria para calcular hash, firma y reglas; no se envía a ningún servidor. La reputación es un historial en memoria de la sesión y no se persiste. No hay telemetría saliente.

## Verificación de firma

`FileInspector.VerifySignature` usa el ciclo documentado de WinVerifyTrust: `WTD_STATEACTION_VERIFY=1`, y siempre `WTD_STATEACTION_CLOSE=2` con el mismo `hWVTStateData`, incluso si la verificación falla. Se liberan también la estructura nativa y la cadena del archivo. La consulta usa solo caché local de revocación para no depender de Internet.

Los códigos se mapean a estados verificables: `SignedTrusted`, `Unsigned`, `SignedUntrusted`, `ChainNotVerifiable` y `Unknown`. Una firma válida no implica inocuidad y una firma ausente no implica malware; la cadena no verificable por falta de caché es una señal débil, nunca evidencia crítica.

## Colas y visibilidad

Las observaciones críticas (canarios, manipulación de manifiesto, C2, reutilización de PID, saturación) usan una cola prioritaria drenada antes que la normal. La coalescencia se aplica después de registrar el primer evento; los descartes reales se contabilizan y elevan el estado a `degraded`. Si un `FileSystemWatcher` informa de error, se marca degradación, se descarta y se recrea; la pérdida nunca se oculta como protección completa.

## Canarios

Los ficheros señuelo se crean con atributos oculto, sistema y solo lectura, y con ACL restringida a SYSTEM, administradores y usuario del servicio. Su baseline se guarda en `canaries.json` bajo `%AEGIS_DATA_DIR%`, con un HMAC-SHA256 cuya clave **aleatoria de 32 bytes se persiste** en `canary.key` protegida con DPAPI del usuario del servicio; no se deriva de nuevo en cada arranque. El manifiesto lleva versión, clave de versión y firma canonicalizada; una versión anterior, aunque estuviera firmada, se rechaza como downgrade. Si el manifiesto se edita o corrompe se conserva como `canaries.invalid-*.json`, no se usa como baseline y se genera la bandera `canary_manifest_tampered`, puntuada como evidencia crítica local. Los manifiestos heredados sin versión se migran una sola vez. `RotateKey()` permite sustituir la clave y volver a firmar las baselines conservadas.

Este HMAC detecta edición casual o corrupción, **no** resiste a un proceso con los mismos privilegios que puede recalcular la clave DPAPI y volver a firmar: sin controlador en kernel no hay una frontera de integridad fuerte. La protección real sigue siendo la comparación del hash del fichero señuelo frente a la baseline.

## Cuarentena

- Cifrado AES-GCM con nonce aleatorio por elemento.
- Metadatos protegidos con DPAPI `LocalMachine`.
- Validación estricta de ruta antes de cualquier movimiento; nunca se aceptan rutas relativas, raíces ni rutas del producto.
- La restauración comprueba integridad y sobrescribe solo previa confirmación explícita.
- El purgado y la restauración retiran las reglas WFP huérfanas asociadas a la amenaza.

## Actualizaciones

El instalador publica desde el código fuente con `dotnet publish` en un directorio temporal, verifica los ejecutables, comprueba que no haya procesos propios en ejecución y sustituye la instalación anterior mediante una copia de seguridad que se restaura si falla la copia. No hay canal de actualización automática de firmas ni de componentes en esta versión. Cualquier mecanismo de autoactualización futuro debe verificar firma digital y hash antes de ejecutarse; las actualizaciones de firmas serán opcionales y no serán necesarias para que la protección local siga funcionando.

## No hacer

- No desactive Microsoft Defender, Bitdefender ni otro producto de seguridad para ejecutar las pruebas EICAR. Si **Ayuda → Ejecutar prueba EICAR** informa de que la muestra fue bloqueada antes del análisis, ese es el resultado: Aegis no la sustituye ni la presenta como detectada por su motor.
- No exponga el puerto 8787 mediante reglas de firewall de entrada.
- No interprete un veredicto `Allow` como garantía de inocuidad: es una decisión con umbrales locales, no una certificación.
