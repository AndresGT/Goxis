# Demo de rutas Goxis

Ejecuta desde la raíz del repositorio:

```powershell
go run ./examples/appdemo
```

Si el puerto 8080 ya está ocupado, cambia el listener sin modificar el demo:

```powershell
$env:GOXIS_APPDEMO_ADDR = '127.0.0.1:18080'
go run ./examples/appdemo
```

El demo genera tokens de access para `demo-admin` y `demo-viewer`, y los imprime en consola. El `viewer` solo tiene permiso general `read`; el rol `admin` tiene `*`. La clave del panel se conserva en `logs/appdemo-jwt.key` para mantener válida su cookie después de reiniciar. En aplicaciones reales, configura `JWT_SECRET` con al menos 32 bytes aleatorios y guárdalo en un gestor de secretos.

| Ruta | Acceso | Resultado esperado |
| --- | --- | --- |
| `GET /api/public` | Pública | `200` sin token |
| `GET /api/public/private` | Privada, sin rol requerido | `200` con admin o viewer; `401` sin access token |
| `GET /api/public/admin` | Requiere el rol `admin` | `200` con admin; `403` con viewer; `401` sin token |
| `GET /api/public/member` | Privada, sin rol requerido | `200` con cualquier access token válido |
| `GET /api/public/rate-limited` | Pública, 2 solicitudes/minuto | `200` en las primeras dos; después `429` |
| `GET /api/public/queued` | Pública, 1 handler activo y 1 en espera | `200`; una tercera petición simultánea recibe `503` |

Las cuatro rutas se registran juntas en un solo `public.RegisterRoutes(...)`. Cada ruta tiene método y path únicos. `RateLimit`, `MaxConcurrent` y `QueueLimit` se aplican individualmente a cada combinación de método y path.

Ejemplos PowerShell, reemplazando el token por el valor impreso al iniciar:

```powershell
curl.exe http://localhost:8080/api/public
curl.exe http://localhost:8080/api/public/private -H "Authorization: Bearer <ADMIN_TOKEN>"
curl.exe http://localhost:8080/api/public/admin -H "Authorization: Bearer <VIEWER_TOKEN>"
curl.exe http://localhost:8080/api/public/member -H "Authorization: Bearer <VIEWER_TOKEN>"
```

## Verificación del piloto

Con el demo encendido en una terminal, ejecuta el smoke check en otra. Copia los tokens impresos al iniciar:

```powershell
.\examples\appdemo\smoke-check.ps1 -AdminToken '<ADMIN_TOKEN>' -ViewerToken '<VIEWER_TOKEN>' -BaseUrl 'http://127.0.0.1:18080'
```

El script valida lectura pública (`200`), rechazo sin token (`401`), acceso admin (`200`), denegación al viewer (`403`), rate limit (`429`), saturación de cola (`503`) y que el flujo SSE del panel acepte la sesión de administrador. La prueba consume el límite del endpoint dedicado; reinicia el demo antes de repetirla para reiniciar sus contadores en memoria.

Para comprobar el apagado ordenado, mantén solicitudes a `/api/public/queued` activas y pulsa `Ctrl+C` en la terminal del demo. El servidor deja de aceptar conexiones, espera hasta 10 segundos por solicitudes activas y luego cierra el escritor de logs. Si se agota ese plazo, el cierre devuelve un error visible.

Estas verificaciones son un smoke test local, no un benchmark ni una garantía de comportamiento bajo tráfico de producción. Antes de desplegar varias instancias, recuerda que rate limits y colas son locales al proceso.

El demo configura CORS para los orígenes de desarrollo declarados y permite credenciales de navegador para la sesión por cookie. No instala `OriginGuard`, así que las rutas públicas también se pueden abrir directamente. Un frontend separado debe usar `credentials: "include"`; no se acepta `*` junto con credenciales. CORS no autentica clientes: las rutas privadas usan access tokens y RBAC.

El panel se limita a loopback y queda en `http://127.0.0.1:8080/_goxis/admin`. Inicia sesión con usuario `admin` y contraseña `admin`. Esas credenciales son exclusivas para desarrollo y no deben usarse en una aplicación real. El panel emite una cookie de sesión HttpOnly mediante `security/token`; no pide ni guarda tokens en el navegador. La interfaz incluida se sirve en el mismo origen y usa la cookie automáticamente; `AllowCredentials` en CORS permite además que los orígenes de desarrollo explícitos hagan llamadas con cookie.

El demo deja `SecureCookie` desactivado para funcionar por HTTP en loopback. Si lo sirves detrás de un reverse proxy que termina TLS, establece `GOXIS_ADMIN_SECURE_COOKIE=true`; en HTTPS directo Goxis marca la cookie `Secure` automáticamente.

Los logs se escriben en `logs/goxis-appdemo.log` y se conservan al reiniciar. La rotación mantiene cinco archivos de hasta 10 MiB cada uno. El panel también carga las líneas recientes de esos archivos al iniciar.
