# Seguridad y privacidad

## Sin credenciales externas

El producto no usa claves de API, cuentas de usuario ni servicios de inferencia. No existen archivos de credenciales ni variables de entorno secretas. Toda la lógica de detección y decisión se ejecuta en el equipo.

## Token local y protección de la API

- La UI recibe el token del archivo `ui-token`, inyectado por WebView2 en la página cargada.
- El token local **no es efímero**: se genera al arrancar el servicio y permanece válido hasta el siguiente arranque. No se envía fuera de `127.0.0.1`; reinicie el servicio para invalidarlo.
- El archivo `ui-token` se crea con ACL que solo concede acceso a SYSTEM, administradores y el usuario del servicio. Si ya existía con permisos débiles, se repara automáticamente al cargarlo.
- Escucha solo en loopback.
- Middleware rechaza cualquier `Host` distinto de `127.0.0.1` / `localhost` / `[::1]`.
- Authorization Bearer obligatoria para `/api`.
- CSP restrictiva, `X-Frame-Options: DENY`, `nosniff` y `no-referrer`.
- WebView2 sin DevTools, menú contextual, autoguardado de contraseñas, autocompletado, host objects ni mensajería web.

## Privacidad de los datos

Las observaciones y decisiones se escriben únicamente en `events.jsonl` y `threats.jsonl` bajo `%AEGIS_DATA_DIR%`, con ACL restringida. El contenido de los ficheros analizados se procesa en memoria para calcular hash, firma y reglas; no se envía a ningún servidor. La reputación es un historial en memoria de la sesión y no se persiste. No hay telemetría saliente.

## Canarios

Los ficheros señuelo se crean con atributos oculto, sistema y solo lectura, y con ACL restringida a SYSTEM, administradores y usuario del servicio. Su baseline se guarda en `canaries.json` bajo `%AEGIS_DATA_DIR%`. Sin un controlador en kernel no es posible impedir que un proceso con los privilegios del usuario altere estos ficheros: la detección se basa en comparar el hash del baseline.

## Cuarentena

- Cifrado AES-GCM con nonce aleatorio por elemento.
- Metadatos protegidos con DPAPI `LocalMachine`.
- Validación estricta de ruta antes de cualquier movimiento; nunca se aceptan rutas relativas, raíces ni rutas del producto.
- La restauración comprueba integridad y sobrescribe solo previa confirmación explícita.
- El purgado y la restauración retiran las reglas WFP huérfanas asociadas a la amenaza.

## Actualizaciones

El instalador publica desde el código fuente con `dotnet publish` y reemplaza los binarios en una operación controlada. No hay canal de actualización automática de firmas ni de componentes en esta versión. Cualquier mecanismo de autoactualización futuro debe verificar firma digital y hash antes de ejecutarse; las actualizaciones de firmas serán opcionales y no serán necesarias para que la protección local siga funcionando.

## No hacer

- No desactive Microsoft Defender, Bitdefender ni otro producto de seguridad para ejecutar las pruebas EICAR.
- No exponga el puerto 8787 mediante reglas de firewall de entrada.
- No interprete un veredicto `Allow` como garantía de inocuidad: es una decisión con umbrales locales, no una certificación.
