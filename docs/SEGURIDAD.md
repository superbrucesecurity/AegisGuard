# Seguridad y privacidad

## Claves

- `LIQUID_API_KEY` existe únicamente en `%AEGIS_DATA_DIR%\gateway.env` (por defecto `C:\ProgramData\AegisGuard\gateway.env`), legible por SYSTEM, administradores y el usuario instalador.
- `Aegis.Service` solo recibe `AEGIS_GATEWAY_KEY`, una clave aleatoria de 256 bits que persiste cifrada con DPAPI `LocalMachine` en `config.json`.
- La UI no conoce la clave de pasarela: recibe el token local del archivo `ui-token`, inyectado por WebView2 en la página cargada.
- El token local **no es efímero**: se genera al arrancar el servicio y permanece válido hasta el siguiente arranque. No se envía fuera de `127.0.0.1`; reinicie el servicio para invalidarlo.

## Minimización de datos

El clasificador cloud recibe como máximo:

- prefijo de 12 caracteres del SHA-256;
- tipo de fichero y bucket de tamaño;
- estado de firma y reputación;
- hasta 16 banderas de comportamiento y 16 IDs de regla;
- tipo de evento.

**No se envían** la ruta completa, el contenido del fichero, nombres de usuario ni argumentos de procesos. Las respuestas se validan (etiqueta, probabilidades, rango de tokens y suma de distribución) antes de influir en una decisión.

## Protección de la API local

- Escucha solo en loopback.
- Middleware rechaza cualquier `Host` distinto de `127.0.0.1` / `localhost` / `[::1]`.
- Authorization Bearer obligatoria para `/api`.
- CSP restrictiva, `X-Frame-Options: DENY`, `nosniff` y `no-referrer`.
- WebView2 sin DevTools, menú contextual, autoguardado de contraseñas, autocompletado, host objects ni mensajería web.

## Cuarentena

- Cifrado AES-GCM con nonce aleatorio por elemento.
- Metadatos protegidos con DPAPI `LocalMachine`.
- Validación estricta de ruta antes de cualquier movimiento; nunca se aceptan rutas relativas, raíces ni rutas del producto.
- La restauración comprueba integridad y sobrescribe solo previa confirmación explícita.

## Actualizaciones

El instalador publica desde el código fuente con `dotnet publish` y reemplaza los binarios en una operación controlada. No hay canal de actualización automática firmado en esta vertical slice; cualquier mecanismo de autoactualización futuro debe verificar firma digital y hash antes de ejecutarse.

## No hacer

- No desactive Bitdefender ni otro producto de seguridad para ejecutar las pruebas EICAR.
- No pegue la clave de Liquid en tickets, chats ni logs.
- No exponga el puerto 8787/8790 mediante reglas de firewall de entrada.
- No interprete un veredicto `CLEAN` como garantía de inocuidad.
