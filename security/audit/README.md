# `security/audit`

Registro estructurado de actividad, consulta filtrada y exportación JSON, NDJSON o CSV. `Auditor` escribe mediante `Storage`. Hoy Goxis incluye `MemoryStorage`; no incluye una implementación persistente ni un worker de retención. Para persistencia, implementa la interfaz `Storage` con el cliente/driver que elija la aplicación.

## Uso global del proceso

`Init` configura el auditor global que consumen `RecordQuick`, `QueryQuick` y `ExportQuick`. Inicialízalo una vez al arrancar. Por defecto puedes usar memoria:

```go
if err := audit.Init(audit.Config{Storage: audit.NewMemoryStorage()}); err != nil {
    return err
}

err := audit.RecordQuick(&audit.Event{
    Actor: audit.ActorInfo{ID: userID, Type: "user"},
    Action: audit.ActionInfo{Type: "LOGIN", Category: "AUTH"},
    Result: audit.ResultInfo{Status: "SUCCESS", StatusCode: 200},
    Context: audit.ContextInfo{IPAddress: clientIP, RequestID: requestID},
})
```

Este default es estado mutable compartido por el proceso, apropiado para una aplicación sencilla. `MemoryStorage` es volátil, no se comparte entre réplicas y pierde los eventos al reiniciar. No uses almacenamiento en memoria como auditoría duradera.

## Instancia aislada y consultas restrictivas

Para separar módulos, pruebas o tenants, crea un auditor dedicado y consulta con filtros estrechos. Los filtros combinados se aplican como AND; cada lista acepta cualquiera de sus valores:

```go
storage := audit.NewMemoryStorage()
auditor, err := audit.NewAuditor(audit.Config{Storage: storage})
if err != nil { return err }
defer auditor.Close()

err = auditor.Record(&audit.Event{
    Actor: audit.ActorInfo{ID: userID, Type: "user"},
    Action: audit.ActionInfo{Type: "UPDATE", Category: "DATA"},
    Resource: audit.ResourceInfo{Type: "invoice", ID: invoiceID, Tenant: tenantID},
    Result: audit.ResultInfo{Status: "SUCCESS"},
    Context: audit.ContextInfo{IPAddress: clientIP},
})
if err != nil { return err }

events, err := auditor.Query(ctx, audit.QueryFilter{
    ActorIDs: []string{userID},
    ActionCategories: []string{"DATA"},
    ResourceTypes: []string{"invoice"},
    StartTime: start, EndTime: end,
    Limit: 100,
})
```

Usa `GetByID`, `Count`, `DeleteOlderThan` y `Export` para consultas, limpieza y extracción. Los formatos exportables son `audit.ExportFormatJSON`, `audit.ExportFormatNDJSON` y `audit.ExportFormatCSV`:

```go
err := auditor.Export(ctx, filter, audit.ExportFormatNDJSON, writer)
```

`ctx` cancela lecturas/escrituras en memoria. `Record` es síncrono; los eventos se asignan UUID y timestamp UTC si faltan, y se calcula una huella SHA-256. Esa huella sirve para comprobar una copia del evento, pero no equivale a una cadena firmada ni hace inmutable el almacenamiento.

## Almacenamiento persistente

Implementa `audit.Storage` con los ocho métodos (`Save`, `SaveBatch`, `GetByID`, `Query`, `Count`, `DeleteOlderThan`, `Export`, `Close`) y pásalo en `Config.Storage`. La implementación debe respetar el contexto, la paginación, filtros y la seguridad de concurrencia. Goxis no abre conexiones, no ejecuta migraciones y no importa drivers. En producción, limita los permisos de la cuenta de base de datos y aplica retención según la política del proyecto.

Ejemplo completo: [`examples/auditdemo`](../../examples/auditdemo).
