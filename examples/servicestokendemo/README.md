# Leer un claim específico desde un servicio

Este ejemplo demuestra el flujo que puede ejecutar un servicio Go: recibe el bearer access token, lo valida con `JWTManager.ValidateToken` y extrae `tenant_id` de `Claims.CustomData`. El token es cifrado; el servicio obtiene los claims únicamente después de validar su autenticidad y expiración.

```sh
go run ./examples/servicestokendemo
```

El demo genera claves efímeras y un token en el mismo proceso para correr de forma autónoma. En producción, el emisor conserva la clave privada; el servicio recibe solo la clave pública, la clave AES autorizada para descifrar, y configura el mismo emisor/audiencia. El token llega al servicio por HTTPS.

El servicio verifica `claims.TokenType == token.TokenTypeAccess` antes de usar los claims. No uses refresh tokens como credenciales de acceso a endpoints. Si `tenant_id` falta o no es texto, el ejemplo devuelve error en lugar de aceptar un valor inesperado.
