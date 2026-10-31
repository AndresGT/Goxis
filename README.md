# Goxis

<p align="center"><img src="assets/brand/goxis-logo.jpeg" alt="Logo de Goxis" width="420"></p>

**Goxis** es la capa HTTP y de seguridad de la plataforma. Define su propia API de aplicación, rutas, grupos, contexto, middleware, políticas de acceso y colas por ruta. Usa `net/http` de Go como transporte; no depende de Gin ni Fiber.

> Goxis está listo para iniciar pruebas de integración en una aplicación piloto. La API y los módulos de seguridad siguen evolucionando; revisa las limitaciones de esta guía antes de usarlo en producción.

## Contenido

- [Requisitos e instalación](#requisitos-e-instalación)
- [Inicio rápido](#inicio-rápido)
- [Rutas, grupos y límites](#rutas-grupos-y-límites)
- [Middleware, CORS y autorización](#middleware-cors-y-autorización)
- [Seguridad y tokens](#seguridad-y-tokens)
- [Panel administrativo](#panel-administrativo)
- [Estructura y ejemplos](#estructura-y-ejemplos)
- [Verificación y preparación](#verificación-y-preparación)
- [Licencia](#licencia)

## Requisitos e instalación

- Go `1.27.1` o compatible con la directiva `go` del módulo.
- La dependencia directa `golang.org/x/crypto` se utiliza en los métodos de hashing de contraseñas. Goxis no requiere Gin, Fiber ni una biblioteca JWT externa.

Añade el módulo al proyecto:

```sh
go get github.com/AndresGT/Goxis
```

## Inicio rápido

Crea la aplicación en el inicializador, registra rutas desde grupos y deja `main` para iniciar el servidor:

```go
package main

import (
    "log"
    "net/http"

    goxis "github.com/AndresGT/Goxis/app"
)

func main() {
    app := goxis.New()
    api := app.Group("/api/v1")

    err := api.RegisterRoutes([]goxis.Route{
        {
            Method: goxis.GET,
            Path:   "/health",
            Handler: func(ctx *goxis.Context) error {
                return ctx.JSON(http.StatusOK, map[string]string{"status": "ok"})
            },
        },
    })
    if err != nil {
        log.Fatal(err)
    }
    if err := app.Run(":8080"); err != nil {
        log.Fatal(err)
    }
}
```

Goxis valida método, ruta, handler y conflictos al registrar. Los parámetros dinámicos aceptan `:id` o `{id}` y se leen con `ctx.Param("id")`. Los handlers responden con `ctx.JSON`, `ctx.Text` u otros helpers de `Context`.

## Rutas, grupos y límites

Los módulos registran sus rutas dentro del grupo que recibe la aplicación:

```go
func RegisterProductRoutes(api *goxis.Group) error {
    products := api.Group("/products")
    return products.RegisterRoutes([]goxis.Route{
        {Method: goxis.GET, Path: "/", Handler: listProducts, RateLimit: 60},
        {
            Method: goxis.POST, Path: "/sync", Handler: syncProducts,
            Protected: true, Roles: []string{"admin"},
            MaxConcurrent: 2, QueueLimit: 8,
        },
    })
}
```

Cada ruta puede definir `Protected`, `Roles`, `Permissions`, `RateLimit`, `MaxConcurrent` y `QueueLimit`. El rate limit se aplica por usuario autenticado cuando el authorizer valida una identidad; sin identidad válida, usa la IP de `RemoteAddr`. Los límites y colas son locales al proceso y a cada instancia. El exceso de rate limit responde `429`; una cola llena responde `503`.

Los grupos heredan middleware y políticas. Los roles y permisos heredados no se eliminan en grupos hijos. Consulta [app/README.md](app/README.md) para el comportamiento completo del router, handlers, servidor, colas y panel.

## Middleware, CORS y autorización

Configura el middleware desde el inicializador de rutas. Al aplicarse a un `*goxis.App`, se registra en la aplicación:

```go
app := goxis.New(goxis.WithAuthorizer(authorizer))

middleware.CORS(middleware.CORSConfig{
    AllowedOrigins: []string{"https://panel.example.com"},
    AllowedMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
    AllowedHeaders: []string{"Authorization", "Content-Type", "Idempotency-Key"},
})(app)

api := app.Group("/api/v1")
```

`middleware.RBAC` valida el access token, añade claims al contexto y autoriza roles/permisos antes de ejecutar el handler. Las rutas protegidas responden `401` sin identidad válida y `403` sin permisos suficientes. CORS controla lo que el navegador puede leer; no sustituye autenticación ni autorización. `OriginGuard` es una opción explícita para rechazar orígenes ausentes o no registrados.

Más detalles y ejemplos: [middleware/README.md](middleware/README.md).

## Seguridad y tokens

Los paquetes de seguridad se encuentran en `security/`:

- `security/token`: generación y validación de access/refresh tokens cifrados, claims, expiración y rotación de refresh; soporta almacenamiento en memoria, Redis o SQL mediante sus interfaces.
- `security/crypto`: hashing de contraseñas con Argon2id, bcrypt, scrypt y PBKDF2; cifrado AES-GCM y valores aleatorios.
- `security/audit`: eventos, filtros y exportación en memoria a CSV, JSON o NDJSON.
- `security`: niveles y errores comunes.

Goxis implementa su formato de token con primitivas criptográficas estándar; no usa una biblioteca JWT externa. Antes de producción, define gestión/rotación de claves, persistencia compartida para varias instancias y expiraciones apropiadas. La revocación de refresh no invalida access tokens ya emitidos antes de que expiren. La guía de cada paquete documenta configuración y límites:

- [Tokens y sesiones](security/token/README.md)
- [Crypto](security/crypto/README.md)
- [Auditoría](security/audit/README.md)
- [Políticas y niveles](security/README.md)

## Panel administrativo

El panel opcional se sirve desde el mismo listener, por defecto en `/_goxis/admin`. Incluye logs, grupos y rutas, historial reciente por ruta, colas/rechazos y métricas del proceso Go. Usa una sesión de cookie `HttpOnly` y un flujo SSE para actualizar la interfaz; las rutas del panel se excluyen de los access logs y de las métricas de la API.

Configúralo con `goxis.WithAdminPanel(...)`, un hash de contraseña y un `TokenManager` con secreto persistente. En HTTPS directo, Goxis marca la cookie `Secure`; detrás de un proxy que termina TLS, establece `SecureCookie: true`. Las métricas y el historial de solicitudes son muestras en memoria; los logs pueden persistir en archivo. El almacenamiento de colas y rate limits también es por proceso.

`examples/appdemo` usa `admin/admin` solo para desarrollo local. No reutilices esas credenciales ni sus secretos de ejemplo. Consulta [app/README.md](app/README.md#panel-local-de-administración) y [examples/appdemo/README.md](examples/appdemo/README.md).

## Estructura y ejemplos

```text
app/                    Aplicación HTTP, router, contexto, servidor y panel
middleware/             CORS, autenticación por token y RBAC
security/               Tokens/sesiones, crypto, auditoría y políticas
log/                    Logger global/instanciado y formatos de salida
assets/brand/           Logo oficial
examples/
  appdemo/              Rutas públicas/protegidas, grupos, colas y panel
  auditdemo/            Registro y consulta de auditoría
  cryptodemo/            Hashing, cifrado y generación de claves
  logdemo/               Niveles y configuración de logs
  servicestokendemo/     Lectura de claims desde servicios
  tokendemo/             Emisión, validación y rotación de tokens
```

Ejecuta el demo de aplicación:

```sh
go run ./examples/appdemo
```

Los demás ejemplos se ejecutan con `go run ./examples/cryptodemo`, `auditdemo`, `logdemo`, `servicestokendemo` o `tokendemo`. Cada carpeta contiene instrucciones adicionales.

## Verificación y preparación

Ejecuta la suite del repositorio con:

```sh
go test ./...
go vet ./...
go build ./...
```

La cobertura existente se concentra en el router/servidor, logger, CORS y límites de crypto. Aún hace falta ampliar pruebas automatizadas para `security/token`, `security/audit`, autenticación/RBAC, expiración y rotación concurrente, además de fallos de almacenamiento y condiciones de carga. Por eso, el siguiente paso recomendado es una integración piloto con tráfico y dependencias reales, junto con pruebas de carga/seguridad antes de declarar Goxis listo para producción.

## Licencia

Este proyecto se distribuye bajo la licencia [MIT](LICENSE).
