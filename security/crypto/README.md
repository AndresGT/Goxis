# `security/crypto`

Herramientas de hashing de contraseñas, cifrado autenticado y generación de secretos. Argon2id, bcrypt, scrypt y PBKDF2 usan [`golang.org/x/crypto`](https://pkg.go.dev/golang.org/x/crypto); AES-256-GCM y aleatoriedad usan la biblioteca estándar.

## Hash de contraseñas

### Configuración global de la aplicación

`HashPassword` usa el hasher global del proceso. Por defecto es Argon2id con los parámetros de conveniencia de GoKit: 64 MiB de memoria, 3 pasadas, paralelismo 2, salida de 32 bytes y salt de 16 bytes. Si quieres aumentar la política para toda la aplicación, configúrala al iniciar, antes de atender requests:

```go
if err := crypto.ConfigureDefaultHasher(crypto.HasherConfig{
    Algorithm:         crypto.AlgorithmArgon2id,
    Argon2Memory:      128 * 1024, // KiB: 128 MiB
    Argon2Iterations:  4,
    Argon2Parallelism: 2,
    Argon2KeyLength:   32,
    Argon2SaltLength:  16,
}); err != nil {
    return err
}

passwordHash, err := crypto.HashPassword(password)
if err != nil { return err }
valid, err := crypto.VerifyPassword(password, passwordHash)
```

`ConfigureDefaultHasher` cambia la instancia global del paquete: úsala una vez al arrancar, no para alternar configuración por usuario/request. `SetDefaultHasher` acepta una implementación propia de `Hasher`. `VerifyPassword` detecta el algoritmo guardado y verifica los hashes previos durante una migración gradual.

### Hasher explícito y política de mayor costo

Para escoger parámetros por servicio, tenant o tipo de dato, crea el hasher y úsalo directamente. Este ejemplo usa una política más costosa que el default:

```go
hasher, err := crypto.NewHasher(crypto.HasherConfig{
    Algorithm:         crypto.AlgorithmArgon2id,
    Argon2Memory:      128 * 1024,
    Argon2Iterations:  4,
    Argon2Parallelism: 4,
    Argon2KeyLength:   32,
    Argon2SaltLength:  16,
})
if err != nil { return err }

encoded, err := hasher.Hash(password)
if err != nil { return err }
ok, err := hasher.Verify(password, encoded)
if err != nil { return err }
if hasher.NeedsUpgrade(encoded) { /* rehashear después de una autenticación exitosa */ }
```

Valida el costo con carga y memoria disponibles para evitar saturar el servicio bajo autenticaciones concurrentes. Goxis limita los parámetros al crear y al verificar hashes guardados (Argon2id, scrypt y bcrypt), y rechaza contraseñas mayores de 1024 bytes. bcrypt no admite más de 72 bytes: Goxis pre-hashea contraseñas mayores con SHA-256 + Base64 para conservar compatibilidad con GoKit.

### Algoritmos y presets GoKit

`GoKitHasherConfig(algorithm)` devuelve los presets de GoKit; los helpers `HashWith...` usan esos presets:

| Helper / algoritmo | Configuración predeterminada |
| --- | --- |
| `HashPassword` / Argon2id | 64 MiB, 3 pasadas, paralelismo 2, salida 32 B, salt 16 B |
| `HashWithBcrypt` | cost 12 |
| `HashWithScrypt` | N=16384, r=8, p=1, salida 32 B, salt 16 B |
| `HashWithPBKDF2` | HMAC-SHA256, 600 000 iteraciones, salida 32 B, salt 16 B |

También puedes elegirlo como default global (`ConfigureDefaultHasher`) o crear una instancia aislada con `NewHasher(HasherConfig{Algorithm: ...})`. Los formatos codifican algoritmo, salt y parámetros. `NeedsUpgrade` compara contra el hasher global configurado.

## Cifrado AES-256-GCM

### Clave global

Las funciones `EncryptString`, `DecryptString`, `EncryptBytes` y `DecryptBytes` usan una única clave global del proceso. Cárgala desde un secret manager al inicio; Goxis no genera una clave global implícita:

```go
key, err := base64.StdEncoding.DecodeString(os.Getenv("GOXIS_ENCRYPTION_KEY"))
if err != nil { return err }
if err := crypto.SetEncryptionKey(key); err != nil { return err } // exactamente 32 bytes

sealed, err := crypto.EncryptString("dato sensible")
plain, err := crypto.DecryptString(sealed)
```

### Cifrador explícito

Para aislar claves por módulo/tenant, evita el estado global y crea una instancia:

```go
key, err := crypto.GenerateEncryptionKey()
if err != nil { return err }
vaultCipher, err := crypto.NewAESEncrypter(key)
if err != nil { return err }
sealed, err := vaultCipher.EncryptString("secreto")
plain, err := vaultCipher.DecryptString(sealed)
```

Cada cifrado usa nonce aleatorio y autenticación GCM; la salida es Base64 URL-safe sin padding. Guarda y rota la clave fuera del repositorio. Perderla impide descifrar los datos; usa claves anteriores durante la ventana de rotación necesaria.

## Generación aleatoria

`RandomBytes`, `RandomString`, `RandomHex`, `GenerateUUID`, `GenerateAPIKey` y `GenerateNumericCode` usan `crypto/rand`. Ejemplo:

```go
apiKey, err := crypto.GenerateAPIKey("billing") // billing_<hex>
otp, err := crypto.GenerateNumericCode(6)
```

Ejemplo ejecutable de los cuatro algoritmos de contraseña, AES y API keys: [`examples/cryptodemo`](../../examples/cryptodemo).
