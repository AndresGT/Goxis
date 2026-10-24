# Demo de rutas Goxis

Ejecuta desde la raíz del repositorio:

```powershell
go run ./examples/appdemo
```

Si no existe `JWT_SECRET`, el demo crea una clave aleatoria temporal, genera tokens de access para `demo-admin` y `demo-viewer`, y los imprime en consola. El `viewer` solo tiene permiso general `read`; el rol `admin` tiene `*`. Esa clave desaparece al reiniciar, así que se generan tokens nuevos cada vez.

| Ruta | Acceso | Resultado esperado |
| --- | --- | --- |
| `GET /api/public` | Pública | `200` sin token |
| `GET /api/public/private` | Privada, sin rol requerido | `200` con admin o viewer; `401` sin access token |
| `GET /api/public/admin` | Requiere el rol `admin` | `200` con admin; `403` con viewer; `401` sin token |
| `GET /api/public/member` | Privada, sin rol requerido | `200` con cualquier access token válido |

Las cuatro rutas se registran juntas en un solo `public.RegisterRoutes(...)`. Cada ruta tiene método y path únicos. `RateLimit`, `MaxConcurrent` y `QueueLimit` se aplican individualmente a cada combinación de método y path.

Ejemplos PowerShell, reemplazando el token por el valor impreso al iniciar:

```powershell
curl.exe http://localhost:8080/api/public
curl.exe http://localhost:8080/api/public/private -H "Authorization: Bearer <ADMIN_TOKEN>"
curl.exe http://localhost:8080/api/public/admin -H "Authorization: Bearer <VIEWER_TOKEN>"
curl.exe http://localhost:8080/api/public/member -H "Authorization: Bearer <VIEWER_TOKEN>"
```

El demo configura CORS, pero no instala `OriginGuard`, para permitir abrir la ruta pública en la barra del navegador. CORS no autentica clientes; las rutas privadas usan access tokens y RBAC.
