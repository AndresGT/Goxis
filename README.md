# Goxis

Goxis is the platform's own HTTP application and routing layer. It provides a framework-owned `App`, route groups, request `Context`, middleware, and group access policies. The HTTP transport uses Go's standard library internally; application modules register routes through Goxis APIs.

## Project layout

```text
.
├── app/                                     # HTTP application, router and request context
├── log/                                     # Global and instance logger
├── middleware/                              # CORS, token auth and RBAC
├── security/                                # crypto, token/session, audit and shared policy
└── examples/                                # Runnable module demos
    ├── appdemo/                             # Public/private/role route demo
    ├── auditdemo/
    ├── cryptodemo/
    ├── logdemo/
    ├── servicestokendemo/
    └── tokendemo/
```

The core lives in `app/` and its package name is `goxis`, so application code uses `goxis.New()`. The `examples/appdemo` separates startup (`main.go`), initialization (`route.go`) and bulk route declarations/handlers (`registerroute.go`). Modules expose a registration function that accepts the group assigned by the application.

```go
server, tokens, err := InitRoutes()
if err != nil {
	log.Fatal(err)
}
_ = tokens // el demo imprime sus tokens para las peticiones de prueba
if err := server.Run(":8080"); err != nil {
	log.Fatal(err)
}
```

```go
// examples/appdemo/route.go
func InitRoutes() (*goxis.App, DemoTokens, error) {
	app := goxis.New(goxis.WithAuthorizer(authorizer))
	api := app.Group("/api")
	if err := RegisterDemoRoutes(api); err != nil { return nil, DemoTokens{}, err }
	return app, demoTokens, nil
}
```

## Route groups and policies

Groups can inherit middleware, roles, and permissions. `WithRoles` requires every listed role. Permissions declared by a group are all required; child groups inherit those restrictions. Route-level `goxis.Route.Roles` accepts any of its listed roles.

```go
admin := api.Group("/admin",
	goxis.WithRoles("admin"),
	goxis.WithPermissions("users:read"),
)
err := users.RegisterRoutes(admin.Group("/users"))
```

Goxis owns route registration and per-route access, rate limit, and queue settings through `app.Group.RegisterRoutes([]goxis.Route{...})`. Configure token validation and role grants with the middleware authorizer passed to `goxis.New`; see [middleware/README.md](middleware/README.md) for the complete setup and method-to-permission mapping.

The platform connects an `Authorizer` with `goxis.WithAuthorizer(...)`. It evaluates the accumulated policy before the route handler. A route with a policy fails closed with an internal server error if the app has no authorizer configured; an unauthenticated request receives 401 and an identity without the required role/grant receives 403.

## CORS

CORS and the optional strict `OriginGuard` are configured in the route initializer, keeping `main` focused on starting the app. When either middleware is applied to a Goxis app, it registers on that app; for another `http.Handler`, it returns the usual wrapped handler. Origins are explicit by default; the wildcard `"*"` is allowed only when credentials are disabled. Invalid origins, methods, headers, or a preflight cache over 24 hours fail closed.

```go
import (
	goxis "github.com/AndresGT/Goxis/app"
	"github.com/AndresGT/Goxis/middleware"
)

func InitRoutes() (*goxis.App, error) {
	app := goxis.New()
	allowedOrigins := []string{"https://panel.example.com"}
	middleware.OriginGuard(allowedOrigins...)(app)
	middleware.CORS(middleware.CORSConfig{
		AllowedOrigins: allowedOrigins,
		AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders: []string{"Authorization", "Content-Type", "Idempotency-Key"},
	})(app)
	return app, nil
}
```

When omitted, methods default to `GET`, `HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, and `OPTIONS`; headers default to `Authorization` and `Content-Type`. Omitted origins allow no browser origin. Preflight requests are answered before route matching, and a preflight with a disallowed origin, method, or header receives `403`. A regular request from a disallowed origin still reaches its route, but the browser will not expose the response to page code: CORS is a browser policy, not authentication or authorization.

For local development, `localhost:3030` is accepted as shorthand for `http://localhost:3030`. Use a full `http://` or `https://` origin for other hosts.

`OriginGuard` returns `403` for missing or unregistered `Origin` headers, including direct browser navigation and `curl`. Browsers send the allowed frontend origin for cross-origin API requests. This header can be forged by non-browser clients, so keep authentication and authorization on protected routes.

## Ejecutar la prueba

```sh
go run ./examples/appdemo
```

The demo includes a public endpoint, a private endpoint, a group restricted to the `admin` role, and a private group without a role restriction. It prints temporary admin/viewer access tokens so you can try both authorization outcomes. See [examples/appdemo/README.md](examples/appdemo/README.md) for the routes and PowerShell requests. Each `goxis.Route` can set `Protected`, `RateLimit`, `MaxConcurrent`, `QueueLimit`, and role/permission requirements. Goxis enforces these route policies; the middleware authorizer validates the access token and resolves its roles and grants. `QueueLimit` bounds waiting requests, while `MaxConcurrent` bounds active handlers.

Goxis logs every HTTP request after its middleware and route handler finish, including CORS preflights and 404/429/503 responses, in the Gin-style access format:

```text
[GOXIS] 2026/10/23 - 03:35:33 | 200 |   4.23ms |    179.51.107.0 | POST     "/api/v0/products/sync"
```

The status is green for 2xx, blue for redirects, yellow for 4xx, and red for 5xx. When the logger is configured for JSON, requests remain structured JSON records. Common credential query parameters are redacted in access logs; avoid sending secrets in URLs.

## Seguridad y tokens

Goxis incluye `security/token` para emitir y validar tokens compactos JOSE cifrados con firma Ed25519 y AES-256-GCM, con rotación de refresh y almacenamientos intercambiables en memoria, Redis o SQL. La guía completa de configuración, interoperabilidad y operación está en [security/token/README.md](security/token/README.md).

El ejemplo de emisión, lectura de claims y rotación se ejecuta con `go run ./examples/tokendemo` tras configurar `JWT_SECRET` con al menos 32 bytes aleatorios.

## Módulos de seguridad

`security/crypto` usa `golang.org/x/crypto` para Argon2id (default), bcrypt, scrypt y PBKDF2 con los presets de GoKit. AES-256-GCM y valores aleatorios usan Go estándar. Revisa la [guía crypto](security/crypto/README.md) para parámetros y configuración.

`security/token` contiene tokens compactos cifrados y el administrador de sesiones. `security/audit` ofrece eventos, filtros, almacenamiento en memoria y exportación CSV/JSON/NDJSON. Para producción distribuida, inyecta implementaciones persistentes de `SessionStore` y `audit.Storage` (Redis o SQL, con el cliente/driver elegido por el proyecto). `security` define políticas por nivel y errores comunes.

Guías: [crypto](security/crypto/README.md), [tokens y sesiones](security/token/README.md), [auditoría](security/audit/README.md), [middleware](middleware/README.md).

El núcleo tiene su propia guía de [rutas, políticas y colas](app/README.md); los niveles/errores comunes se explican en [security](security/README.md). El logger describe el [default global y las instancias aisladas](log/README.md).

Ejemplos ejecutables adicionales: `go run ./examples/cryptodemo` muestra hash, cifrado y generación de claves; `go run ./examples/auditdemo` muestra registro, consulta y exportación de auditoría; `go run ./examples/servicestokendemo` valida un token desde un servicio y extrae un claim específico.
