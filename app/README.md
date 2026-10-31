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

`RateLimit` limita solicitudes por usuario autenticado por minuto y ruta cuando el `Authorizer` implementa `IdentityAuthenticator`; si no hay una identidad verificada, usa la IP del cliente. `middleware.RBAC` valida el access token antes de consumir el cupo y deja `Claims.UserID` disponible en `Context.Identity()`. Los tokens sin validar y los refresh tokens no se usan como identidad. `MaxConcurrent` limita handlers en ejecución; `QueueLimit` limita los que esperan. Al llenarse la cola se responde 503 y al superar rate limit, 429. Estos contadores viven en memoria, por ruta y por instancia.

El panel administrativo incluye la vista **Colas**, que muestra handlers activos, solicitudes en espera, rechazos por cola llena y cancelaciones mientras esperan. También conserva hasta 100 fallos por ruta con motivo, IP, URL saneada y Request ID. `queue_full` corresponde a una respuesta 503; `request_canceled_while_waiting` indica que el cliente cerró la solicitud antes de ser admitido. Esta vista se actualiza por SSE y los datos son volátiles: se reinician con el proceso.

Los handlers y middlewares deben devolver errores centinela (`ErrUnauthenticated`, `ErrForbidden`, etc.) en lugar de escribir la respuesta de error directamente. El core los traduce a JSON con la forma estable `{"error":"unauthorized"}` y sus códigos HTTP correspondientes. Las respuestas de error de rutas, del panel, rate limit, cola llena y errores internos usan la misma forma.

Un `Authorizer` personalizado puede habilitar límites por usuario implementando también:

```go
type IdentityAuthenticator interface {
    Authenticate(ctx *goxis.Context) error // valida y llama ctx.SetAuthenticatedIdentity(userID)
}
```

La IP se obtiene de `RemoteAddr`; Goxis no confía en `X-Forwarded-For` sin configuración explícita de proxy confiable.

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

Al inicio de cada request, Goxis genera un ID aleatorio de 128 bits, ignora cualquier `X-Request-ID` entrante y devuelve el nuevo valor en la respuesta. Está disponible en handlers con `ctx.RequestID()` y aparece como `request_id` en los access logs de texto y JSON. Puedes propagarlo a logs de servicios o auditoría para correlacionar eventos de una misma petición.

## Panel local de administración

Actívalo explícitamente al crear la aplicación. Se sirve en el mismo puerto que el API, por defecto en `/_goxis/admin`; el búfer de logs retiene como máximo 500 líneas recientes.

Genera el hash al iniciar configuración (no guardes la contraseña en texto plano):

```go
passwordHash, err := crypto.HashPassword(os.Getenv("GOXIS_ADMIN_PASSWORD"))
if err != nil { return err }
jwtManager, err := token.NewJWTManager(token.JWTConfig{
    SecretKey: []byte(os.Getenv("JWT_SECRET")), // al menos 32 bytes aleatorios y estable
    AccessTokenDuration: 15 * time.Minute,
})
if err != nil { return err }
app := goxis.New(
    goxis.WithAdminPanel(goxis.AdminPanelConfig{
        AdminUsername: os.Getenv("GOXIS_ADMIN_USERNAME"),
        AdminPasswordHash: passwordHash,
        TokenManager: jwtManager,
        SessionTTL: 15 * time.Minute,
        SecureCookie: os.Getenv("GOXIS_ADMIN_SECURE_COOKIE") == "true",
        LogFilePath: "logs/goxis-admin.log",
        MaxLogEntries: 1000,
        MaxMetricSamples: 4096,
    }),
)
```

La página presenta un formulario de usuario y contraseña. Después del login, Goxis emite una cookie HttpOnly, SameSite Strict y firmada mediante `security/token`; JavaScript no puede leer el token. En HTTPS directo, Goxis activa `Secure` automáticamente. Si TLS termina en un reverse proxy confiable, configura `SecureCookie: true` explícitamente; Goxis no deduce el esquema a partir de `X-Forwarded-Proto`. En desarrollo local HTTP déjalo en `false`, o el navegador no enviará la cookie. El panel recibe cambios mediante un único flujo SSE (`/api/events`), sin sondeo periódico; al reconectar, el servidor envía una instantánea actual y luego los cambios nuevos. Las APIs y el flujo validan la cookie durante la sesión. `MaxLoginAttempts` limita los fallos por IP (5 por defecto) y `LoginLockout` define la ventana y el bloqueo (15 minutos por defecto); los intentos bloqueados responden `429` y `Retry-After`. `App.Close()` libera el escritor de logs; llámalo después de detener el servidor.

La interfaz incluye resumen de tráfico de 12 minutos, estados HTTP, solicitudes totales/activas, latencia media y p95, rutas más consultadas, tabla filtrable de rutas y logs buscables. En **Rendimiento** muestra cada cinco segundos CPU lógicas, `GOMAXPROCS`, goroutines, heap, actividad del GC y límites del servidor HTTP usando el runtime estándar de Go. La memoria corresponde al proceso/runtime; no representa la RAM total del host ni el consumo porcentual de CPU. En Rutas se puede filtrar por grupo, abrir una ruta para consultar sus políticas y revisar solicitudes recientes por status, latencia, IP, URL saneada y Request ID. La página determina el estado de la cookie al servir el HTML; solo una sesión válida abre la conexión SSE. Esa única conexión entrega instantánea y actualizaciones; cambiar filtros o abrir detalles no genera peticiones adicionales. Conserva hasta 5000 solicitudes recientes del búfer configurado por `MaxMetricSamples`. Las rutas del panel se excluyen del access log y de las métricas de la API.

Las sugerencias son señales para investigar, no cambios automáticos: aparecen ante varios `5xx`, latencia p95 alta con muestra suficiente, proporción elevada de `4xx` o volumen sostenido por método. El texto propone qué revisar en lecturas (`GET`), escrituras (`POST`/`PUT`/`PATCH`) y borrados (`DELETE`), incluyendo `RateLimit`, `MaxConcurrent` y `QueueLimit` cuando hay volumen alto. Las cifras de método usan las muestras recientes que quepan en `MaxMetricSamples`; bajo tráfico extremo esa retención puede cubrir menos de cinco minutos.

`LogFilePath` habilita persistencia local con rotación (10 MiB y cinco archivos por defecto). Al reiniciar, las líneas rotadas y actuales se cargan en el búfer reciente. Protege el archivo y las credenciales con permisos adecuados; en despliegues con varias instancias usa almacenamiento compartido externo. El panel comparte el host del API; para mantenerlo local, enlaza el listener a `127.0.0.1`.
