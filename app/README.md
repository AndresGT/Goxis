# `app` — núcleo de Goxis

El paquete se importa como `goxis` y contiene la aplicación HTTP, registro de rutas, grupos, contexto, middleware de handler, políticas de acceso, rate limit y colas por ruta. No depende de Gin, Fiber ni de `net/http` como API de rutas; usa `net/http` internamente como transporte.

## Crear e iniciar una aplicación

Inicializa el `App` y los grupos de rutas fuera de `main`; `Run` queda como arranque del servidor:

```go
func InitRoutes() (*goxis.App, error) {
    app := goxis.New()
    api := app.Group("/api/v1")
    if err := RegisterUserRoutes(api); err != nil { return nil, err }
    return app, nil
}

func main() {
    app, err := InitRoutes()
    if err != nil { log.Fatal(err) }
    log.Fatal(app.Run(":8080"))
}
```

Cada módulo registra sus endpoints en un grupo asignado:

```go
func RegisterUserRoutes(api *goxis.Group) error {
    users := api.Group("/users")
    return users.RegisterRoutes([]goxis.Route{
        {Method: goxis.GET, Path: "/", Handler: listUsers},
        {Method: goxis.GET, Path: "/:id", Handler: getUser},
    })
}
```

El registro valida method/path/handler y duplicados antes de agregar el lote. Los paths dinámicos aceptan `:id` o `{id}`; dentro del handler se leen con `ctx.Param("id")`. Respuestas comunes: `ctx.JSON`, `ctx.Text` y `ctx.Request`.

## Políticas globales, de grupo y de ruta

`WithAuthorizer` se aplica a toda la aplicación. Roles y permisos se heredan desde grupos; los requisitos heredados no se eliminan en un grupo hijo:

```go
app := goxis.New(goxis.WithAuthorizer(rbac))
api := app.Group("/api/v1")
admin := api.Group("/admin", goxis.WithRoles("admin"), goxis.WithPermissions("reports:read"))
```

También puedes aplicar el control a una sola ruta. `Protected` exige identidad; `Roles`, `Permission` y `Permissions` requieren autorización y hacen que la ruta sea protegida automáticamente:

```go
return api.RegisterRoutes([]goxis.Route{
    {Method: goxis.GET, Path: "/public", Handler: publicHandler, RateLimit: 20},
    {Method: goxis.GET, Path: "/profile", Handler: profileHandler, Protected: true},
    {Method: goxis.DELETE, Path: "/users/:id", Handler: deleteUser,
        Roles: []string{"admin"}, Permission: "users", RateLimit: 5},
})
```

El método HTTP compone `Permission` con la acción (`users:read`, `users:create`, `users:edit`, `users:delete`). El `Authorizer` del middleware valida el token antes del handler; 401 significa identidad ausente/no válida y 403 una identidad sin el rol/grant requerido. Consulta [middleware](../middleware/README.md) para grants y claims.

## Limitación de solicitudes y colas

Cada ruta puede fijar controles propios:

```go
{Method: goxis.POST, Path: "/reports", Handler: generateReport,
    Protected: true, MaxConcurrent: 2, QueueLimit: 8, RateLimit: 10}
```

`RateLimit` limita solicitudes por IP por minuto y ruta. `MaxConcurrent` limita handlers en ejecución; `QueueLimit` limita los que esperan. Al llenarse la cola se responde 503 y al superar rate limit, 429. Estos contadores viven en memoria, por ruta y por instancia; cero desactiva el rate limit/cola y deja concurrencia sin límite.

## Middleware de aplicación

`app.Use` agrega middleware que recibe un `*goxis.Context`; `goxis.WithMiddleware(...)` lo agrega a un grupo. Middlewares HTTP externos a la API de handlers se conectan con `middleware.CORS(config)(app)` o se pasan a `RunHandler`. CORS se documenta en [middleware/README.md](../middleware/README.md).

## Servidor

`app.Run(":8080")` inicia el listener con timeouts y límites de cabecera seguros. Ajusta esos valores con `WithHTTPServerConfig`; cero desactiva un timeout. `MaxHeaderBytes: 0` usa el valor predeterminado de `net/http`. En endpoints de streaming puedes establecer `WriteTimeout: 0`.

Para controlar el apagado ordenado, crea el servidor con `NewHTTPServer`, inicia `Serve` en una goroutine y llama `Shutdown(ctx)` cuando recibas la señal de cierre:

```go
server, err := app.NewHTTPServer(":8080", app)
if err != nil { return err }
listener, err := net.Listen("tcp", server.Addr)
if err != nil { return err }
go func() { _ = server.Serve(listener) }()
// al cerrar:
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
defer cancel()
return server.Shutdown(ctx)
```

`RunHandler(addr, handler)` permite envolver el app, por ejemplo con CORS. Goxis imprime al registrar rutas y escribe un access log estilo Gin con fecha, status, duración, IP, método y URI. Oculta automáticamente valores de parámetros comunes de credenciales (`token`, `access_token`, `password`, `api_key`, entre otros); evita de todos modos incluir secretos en URLs. El color del status depende de su clase HTTP y el formato JSON del logger sigue produciendo JSON estructurado.
