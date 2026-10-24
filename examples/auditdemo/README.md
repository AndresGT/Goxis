# Ejemplo de `security/audit`

Ejecuta:

```sh
go run ./examples/auditdemo
```

El programa registra un login exitoso y uno fallido en `MemoryStorage`, consulta por ID del actor e imprime el resultado y la huella calculada. Después exporta los eventos como JSON. El almacenamiento en memoria solo vive durante el proceso; para persistencia inyecta tu implementación de `audit.Storage` en `audit.Config`.
