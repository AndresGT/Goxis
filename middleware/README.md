# Middleware de seguridad de Goxis

El paquete `github.com/AndresGT/Goxis/middleware` valida y lee tokens y resuelve roles/permisos. No registra rutas ni configura sus rate limits o colas; eso pertenece a `app.Route` y `app.Group.RegisterRoutes`.

## Política global de auth y restricciones por grupo

Configura un único `RBAC` durante el arranque y conéctalo al `App`. Los roles se traducen en grants; aplica los requisitos a un grupo para que todas sus rutas los hereden:

```go
rbac := middleware.NewRBAC(jwtManager,
    middleware.Role{Name: "reader", Permissions: []string{"read", "orders:read"}},
    middleware.Role{Name: "operator", Permissions: []string{"read", "orders:read", "orders:edit"}},
    middleware.Role{Name: "admin", Permissions: []string{"*"}},
)
app := goxis.New(goxis.WithAuthorizer(rbac))
api := app.Group("/api/v1")
admin := api.Group("/admin", goxis.WithRoles("admin"))
```

Si este proceso solo valida tokens, usa `token.Manager` con claves públicas y de cifrado; no necesita la clave privada ni capacidad de emitir tokens. `NewRBAC` y `RequireAuth` reciben la interfaz `AccessTokenValidator`, que también acepta `*token.JWTManager`:

```go
validator, err := token.New(token.Config{
    Issuer: "goxis-auth", Audience: []string{"orders-api"},
    VerificationKeys: map[string]ed25519.PublicKey{"key-1": publicKey},
    EncryptionKeys: map[string][]byte{"enc-1": encryptionKey},
})
if err != nil { return nil, err }
rbac := middleware.NewRBAC(validator,
    middleware.Role{Name: "reader", Permissions: []string{"orders:read"}},
)
```

El servicio requiere las claves públicas y AES de confianza correspondientes a los `kid` activos, el mismo issuer y una audiencia que incluya la del token. Mantén la clave privada solo en el servicio emisor.

Las políticas heredadas se combinan: cada rol puesto en opciones de grupo debe estar presente, mientras `Route.Roles` acepta cualquiera de sus roles declarados. Para limitar una ruta individual usa `Protected`, `Roles`, `Permission` o `Permissions` en `goxis.Route`. El authorizer valida access tokens antes del handler; los handlers protegidos pueden tomar claims con `middleware.MustClaims(ctx)`.

## Conectar autorización a la aplicación

Configura el `JWTManager`, define qué permisos concede cada rol y entrega el RBAC al núcleo Goxis:

```go
jwtManager, err := token.NewJWTManager(token.JWTConfig{
    SecretKey:            []byte(os.Getenv("JWT_SECRET")),
    AccessTokenDuration:  5 * time.Minute,
    RefreshTokenDuration: 7 * 24 * time.Hour,
})
if err != nil { return nil, err }

rbac := middleware.NewRBAC(jwtManager,
    middleware.Role{Name: "viewer", Permissions: []string{"read"}},
    middleware.Role{Name: "editor", Permissions: []string{"read", "create", "edit"}},
    middleware.Role{Name: "admin", Permissions: []string{"*"}},
)
app := goxis.New(goxis.WithAuthorizer(rbac))
```

`RBAC` implementa `goxis.Authorizer`: antes de invocar el handler de una ruta protegida valida `Authorization: Bearer <access_token>`, guarda los claims en el contexto y revisa la política que el router adjuntó a la ruta. Token ausente, inválido, expirado o refresh responde `401` y no ejecuta el handler; identidad válida sin rol o permiso requerido responde `403`.

## Definir las rutas en Goxis

Los módulos siguen registrando sus rutas por separado. Los endpoints públicos pueden usar límite y cola sin configurar middleware de auth:

```go
authGroup := app.Group("/api/v1/auth")
err := authGroup.RegisterRoutes([]goxis.Route{
    {Method: goxis.POST, Path: "/signup", Handler: handler.SignUp, RateLimit: 5},
    {Method: goxis.POST, Path: "/signin", Handler: handler.SignIn, RateLimit: 5},
    {Method: goxis.POST, Path: "/refresh", Handler: handler.RefreshToken, RateLimit: 1},
})
if err != nil { return nil, err }
```

Las rutas privadas declaran sus requisitos junto al handler:

```go
users := app.Group("/api/v1/users")
err := users.RegisterRoutes([]goxis.Route{
    {Method: goxis.GET, Path: "/", Handler: handler.List, Roles: []string{"viewer", "editor"}, Permission: "users"},
    {Method: goxis.POST, Path: "/", Handler: handler.Create, Roles: []string{"editor", "admin"}, Permission: "users"},
    {Method: goxis.PATCH, Path: "/:id", Handler: handler.Update, Roles: []string{"editor", "admin"}, Permission: "users"},
    {Method: goxis.DELETE, Path: "/:id", Handler: handler.Delete, Roles: []string{"admin"}, Permission: "users"},
    {Method: goxis.GET, Path: "/export", Handler: handler.Export, Protected: true, Permissions: []string{"users:export"}},
    {Method: goxis.GET, Path: "/report", Handler: handler.Report, Protected: true, MaxConcurrent: 2, QueueLimit: 10},
})
if err != nil { return nil, err }
```

`Protected: true` exige autenticación. Una ruta con `Roles`, `Permission` o `Permissions` también queda protegida automáticamente. El core rechaza la solicitud si no hay un `Authorizer` configurado o la autenticación no se completó.

## Permisos por método

Cuando se asigna `Permission: "users"`, Goxis compone el permiso de recurso y acción según el verbo:

| Método | Permiso requerido |
| --- | --- |
| `GET`, `HEAD` | `users:read` |
| `POST` | `users:create` |
| `PUT`, `PATCH` | `users:edit` |
| `DELETE` | `users:delete` |

Si una ruta requiere roles pero no declara `Permission` ni `Permissions`, se añade la acción general del método (`read`, `create`, `edit`, `delete`). `Permissions` añade requisitos explícitos; todos deben concederse. `Route.Roles` acepta cualquiera de los roles declarados; `goxis.WithRoles` para grupos hereda requisitos que todos deben cumplir.

`NewRBAC` suma los permisos de todos los roles contenidos en `Claims.Roles`. También acepta permisos directos en `Claims.Permissions`. Un grant genérico como `read` permite leer todos los recursos; `users:read` limita la lectura a users. Los comodines admitidos son `*`, `users:*` y `*:read`.

Incluye los roles y permisos en los claims al emitir los tokens:

```go
pair, err := jwtManager.GenerateTokenPair(token.Claims{
    UserID: user.ID.String(),
    Email: user.Email,
    Roles: []string{"editor"},
    CustomData: map[string]any{"displayName": user.Name},
})
```

## Leer claims en el handler

El RBAC valida el token antes de llamar al handler y deja los claims disponibles. En una ruta protegida, usa `MustClaims` directamente:

```go
func Profile(ctx *goxis.Context) error {
    claims := middleware.MustClaims(ctx)
    return ctx.JSON(http.StatusOK, map[string]any{
        "user_id": claims.UserID,
        "email": claims.Email,
        "roles": claims.Roles,
        "custom_data": claims.CustomData,
    })
}
```

`MustClaims` asume que el middleware ya autenticó la solicitud y produce un panic solo si la ruta fue montada sin la protección/authorizer esperados, lo que señala un error de configuración. Para handlers reutilizados también en rutas públicas, usa `ClaimsFromContext`, que devuelve `(claims, ok)`.

`middleware.RequireAuth(jwtManager)` sigue disponible para componer autenticación explícita con `goxis.WithMiddleware`, pero no registra rutas. Al usarlo junto con `NewRBAC`, el authorizer reutiliza los claims ya validados.

## CORS global y política estricta de origen

Registra CORS una vez en el inicializador de rutas. `CORS` configura la política del navegador; `OriginGuard` añade un rechazo HTTP del origen ausente/no permitido. `OriginGuard` no sustituye tokens ni roles y el encabezado `Origin` puede falsificarse fuera del navegador.

```go
func InitRoutes() (*goxis.App, error) {
    app := goxis.New(goxis.WithAuthorizer(rbac))
    origins := []string{"https://panel.example.com", "http://localhost:3030"}
    middleware.OriginGuard(origins...)(app) // regla estricta para todas las rutas
    middleware.CORS(middleware.CORSConfig{
        AllowedOrigins: origins,
        AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
        AllowedHeaders: []string{"Authorization", "Content-Type", "Idempotency-Key"},
        ExposedHeaders: []string{"X-Request-ID"},
        AllowCredentials: true,
        MaxAge: 600,
    })(app)
    // Crear api y registrar las rutas aquí.
    return app, nil
}
```

Para una allowlist más estrecha por ambiente, define solamente los orígenes reales del frontend y los métodos/headers requeridos. No combines `AllowedOrigins: []string{"*"}` con credenciales; se rechaza la configuración. Sin `OriginGuard`, una petición no-browser con origen ausente no queda autenticada por CORS. Un preflight que incumple la política recibe 403. Para desarrollo local, `localhost:3030` se acepta como abreviatura de `http://localhost:3030`.

## Rate limits y colas del core

`RateLimit` permite ese número de solicitudes por IP cada minuto; se implementa en memoria por ruta y por instancia. Si se supera, Goxis responde `429`. No confíes en `X-Forwarded-For` sin un proxy inverso explícitamente confiable; el rate limit usa `RemoteAddr`.

`MaxConcurrent` limita cuántos handlers de una ruta se ejecutan al mismo tiempo. `QueueLimit` fija cuántas solicitudes adicionales pueden esperar; al llenarse la capacidad disponible, Goxis responde `503`. Una solicitud que cancela su contexto mientras espera sale de la cola. Ambos valores son por ruta y proceso; cero significa sin límite/concurrencia ilimitada para `MaxConcurrent`, y sin espera adicional para `QueueLimit`.
