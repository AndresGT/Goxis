# `log`

Logger concurrente para Goxis, basado en el patrón de GoKit. Permite filtrar por severidad, escribir registros de texto o JSON y colorear el nivel en las salidas de texto.

## Instalación

```go
import "github.com/AndresGT/Goxis/log"
```

## Uso rápido

La instancia global escribe en `stdout` por defecto:

```go
log.Info("Servidor iniciado")
log.Warn("Uso de memoria elevado")
log.Error("No se pudo conectar")
log.Success("Usuario autenticado")
log.InfoWithFields("usuario creado", map[string]any{
	"user_id": "usr_123",
	"email":   "ana@example.com",
})
```

También se puede crear una instancia y pasar el destino desde la aplicación. Cualquier `io.Writer` es válido; el paquete no crea ni administra archivos.

```go
var output bytes.Buffer
logger := log.New(
	log.WithWriter(&output),
	log.WithLevel(log.DebugLevel),
	log.WithColor(false),
)
logger.Debug("Este mensaje va al writer elegido por la aplicación")
```

Si no se pasa `WithWriter`, la instancia usa `stdout`.

## Niveles

| Nivel | Uso |
| --- | --- |
| `Trace` | Diagnóstico detallado |
| `Debug` | Depuración |
| `Info` | Eventos habituales |
| `Success` | Operación completada correctamente |
| `Warn` | Situación que merece atención |
| `Error` | Operación fallida |
| `Fatal` | Registra el mensaje y termina el proceso con código 1 |
| `Panic` | Registra el mensaje y ejecuta `panic` |

Cada nivel tiene un color ANSI propio en formato texto. Se puede desactivar con `WithColor(false)`. El formato JSON no incluye secuencias de color para seguir siendo JSON válido.

```go
logger := log.New(log.WithLevel(log.WarnLevel))
logger.Info("se filtra")
logger.Warn("se imprime")
logger.Errorf("falló la solicitud %d", 42)
```

## Formato JSON y campos

```go
logger := log.New(log.WithFormat(log.FormatJSON))
logger.InfoWithFields("solicitud procesada", map[string]any{
	"request_id": "req-42",
	"status":     200,
})
```

Cada línea JSON incluye `time`, `level`, `message` y, si existen, `fields`.

## Opciones

- `WithLevel(level)`: nivel mínimo que se imprime. El valor predeterminado es `Info`.
- `WithWriter(writer)`: destino que proporciona la aplicación. El predeterminado es `os.Stdout`.
- `WithColor(enabled)`: activa o desactiva los colores de texto. Activado por defecto.
- `WithFormat(format)`: usa `FormatText` (predeterminado) o `FormatJSON`.
- `WithTimeFormat(layout)`: formato de hora compatible con `time.Format`; usa fecha y hora por defecto. Un layout vacío omite la marca de tiempo.

Las funciones globales (`Info`, `Warn`, etc.) usan `GetDefault()`. Reemplaza el logger global una sola vez durante el arranque para establecer la política de todo el proceso. Por ejemplo, restringe los logs de producción a warnings/errors y envíalos a stderr:

```go
log.SetDefault(log.New(
	log.WithLevel(log.WarnLevel),
	log.WithWriter(os.Stderr),
	log.WithColor(false),
))
```

La instancia global es compartida por todos los paquetes que usen funciones de paquete. Evita cambiarla por request o por tenant. Para un subsistema que necesita su propio destino, formato o umbral, crea un `*log.Logger` independiente y pásalo como dependencia:

```go
auditLogger := log.New(
	log.WithLevel(log.DebugLevel),
	log.WithWriter(auditWriter),
	log.WithFormat(log.FormatJSON),
)
auditLogger.DebugWithFields("evento revisado", map[string]any{"event_id": eventID})
```

`ParseLevel` y `ParseFormat` convierten valores de configuración. Los errores `ErrInvalidLevel` y `ErrInvalidFormat` se pueden comprobar con `errors.Is`.
