# Ejemplo de `security/crypto`

Ejecuta:

```sh
go run ./examples/cryptodemo
```

El programa genera y verifica hashes Argon2id (default), bcrypt, scrypt y PBKDF2-SHA256 con los parámetros de GoKit. También muestra cifrado/descifrado AES-256-GCM con una clave aleatoria y generación de una API key. Todos los valores son efímeros de demostración: no guardes contraseñas ni claves en logs y no uses las claves generadas por esta ejecución para datos que deban persistir.
