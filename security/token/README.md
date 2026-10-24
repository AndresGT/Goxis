# Tokens de Goxis

`github.com/AndresGT/Goxis/security/token` crea y valida tokens de acceso y de renovación para Goxis y otros servicios Go. No utiliza una dependencia JWT: firma con Ed25519 y cifra con AES-256-GCM mediante la biblioteca estándar.

## Elección del nivel de configuración

El paquete no crea un manager global implícito: crea una instancia al iniciar el servicio y la inyecta donde se emiten/validan tokens. `JWTManager` ofrece la API sencilla con un único secreto. `Manager` ofrece control separado de claves, emisor/audiencia y almacenamiento; es el modo recomendado cuando hay servicios que solo validan.

### Configuración sencilla de la aplicación

Inicializa una instancia `JWTManager` una vez y compártela en el proceso emisor. Si omites `Store`, el manager usa `MemoryStore`, que es volátil y solo sirve para desarrollo/proceso único:

```go
var jwtManager *token.JWTManager

func InitTokens() error {
    var err error
    jwtManager, err = token.NewJWTManager(token.JWTConfig{
        SecretKey: []byte(os.Getenv("JWT_SECRET")), // >=32 bytes aleatorios
        AccessTokenDuration: 5 * time.Minute,
        RefreshTokenDuration: 7 * 24 * time.Hour,
        Issuer: "auth-service",
        Audience: []string{"goxis-api"},
        Store: token.NewMemoryStore(),
    })
    return err
}
```

`JWTManager` deriva claves Ed25519 y AES del mismo secreto. Protege ese secreto como material capaz de emitir y leer tokens. Para rotación de refresh multi-instancia, inyecta `RedisStore` o `SQLStore` en `JWTConfig.Store`.

### Configuración explícita con separación de claves

Define una política más estrecha con access TTL corto, audiencia dedicada, IDs de clave y store compartido. El emisor conserva la clave privada:

```go
issuer, err := token.New(token.Config{
    Issuer: "https://auth.example.com",
    Audience: []string{"payments-api"},
    AccessTTL: 5 * time.Minute,
    RefreshTTL: 12 * time.Hour,
    SigningKeyID: "sign-2026-10",
    SigningKey: signingPrivate,
    EncryptionKeyID: "enc-2026-10",
    EncryptionKeys: map[string][]byte{"enc-2026-10": aesKey},
    Store: redisStore,
})
if err != nil { return err }
pair, err := issuer.Issue(token.IssueOptions{
    UserID: user.ID, Email: user.Email,
    Roles: []string{"billing-reader"},
    Permissions: []string{"payments:read"},
    CustomData: map[string]any{"tenant_id": tenantID},
})
```

Un servicio que solo verifica crea su propio `Manager` con `VerificationKeys`, la clave AES permitida, el mismo `Issuer` y su audiencia. No configura `SigningKey` ni `Store`; `Validate(raw, token.AccessToken)` fija el tipo esperado. Así el servicio puede leer los claims autorizados y verificar firma sin capacidad de emitir tokens.

## API simple tipo GoKit

Para la mayoría de aplicaciones usa `JWTManager`, que permite configurar un solo secreto y trabajar directamente con claims de usuario. El secreto debe tener al menos 32 bytes de material aleatorio. Las dos duraciones se definen en el constructor:

```go
jwtManager, err := token.NewJWTManager(token.JWTConfig{
    SecretKey:            []byte(os.Getenv("JWT_SECRET")),
    AccessTokenDuration:  5 * time.Minute,
    RefreshTokenDuration: 7 * 24 * time.Hour,
})
if err != nil {
    log.Fatal("Error al configurar jwtManager: ", err)
}
```

`JWTManager` separa internamente el secreto en claves Ed25519 y AES usando derivación con dominios distintos. Si no se indica otro `Store`, utiliza memoria para que el demo arranque sin infraestructura. En producción configura `Store: redisStore` (recomendado) o `Store: sqlStore`; el secreto debe ser aleatorio, único por ambiente y mantenerse fuera del repositorio.

Construye los claims de la misma forma en que construyes la respuesta para el usuario. `GenerateTokenPair` comparte la misma sesión entre ambos tokens:

```go
claims := token.Claims{
    UserID: auth.ID.String(),
    Email:  auth.Email,
    CustomData: map[string]any{
        "name": auth.Name,
        "role": auth.Role,
    },
}

pair, err := jwtManager.GenerateTokenPair(claims)
if err != nil {
    return nil, err
}
accessToken := pair.AccessToken
refreshToken := pair.RefreshToken
```

También están disponibles `GenerateAccessToken(claims)` y `GenerateRefreshToken(claims)` por separado. Si se usan por separado, asigna `claims.SessionID` antes de generar ambos para que pertenezcan a la misma sesión. El access es de tipo `token.TokenTypeAccess`; el refresh es `token.TokenTypeRefresh`.

Lee cualquiera de los dos tipos con `ValidateToken`, y verifica el tipo antes de usarlo para la operación solicitada:

```go
claims, err := jwtManager.ValidateToken(req.RefreshToken)
if err != nil || claims.TokenType != token.TokenTypeRefresh {
    return nil, ErrInvalidToken
}
userID := claims.UserID
email := claims.Email
clientData := claims.CustomData
```

En el endpoint de renovación usa `RefreshTokens`, que además consume atómicamente el refresh usado y detecta su reutilización:

```go
pair, err := jwtManager.RefreshTokens(req.RefreshToken)
if err != nil {
    return nil, ErrInvalidToken
}
// Entrega pair.AccessToken y pair.RefreshToken; descarta el refresh anterior.
```

El patrón de validar, leer claims y volver a llamar por separado a `GenerateRefreshToken` no consume el refresh anterior. Para conservar la rotación acordada, usa `RefreshTokens` al renovar.

El ejemplo ejecutable está en `examples/tokendemo`. En PowerShell puedes crear una clave efímera de desarrollo y correrlo así:

```powershell
$env:JWT_SECRET = [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(32))
go run ./examples/tokendemo
```

El programa imprime ambos tokens cifrados y los claims que el manager recupera localmente. No uses esta clave temporal para un servicio real.

### Tamaño

Goxis conserva el `sub` como representación serializada de `Claims.UserID`, usa IDs aleatorios de 128 bits y en la API simple usa `sid` como familia de refresh, evitando repetir `fid`. Esto acorta los tokens sin quitar sus comprobaciones. Aun así, un JWE cifrado con JWS Ed25519 anidado tendrá más segmentos y sobrecarga que un JWT firmado HS256 como el ejemplo de referencia: ese JWT deja el payload visible y no satisface el requisito de cifrado. El tamaño también depende de cuánto se ponga en `Email` y `CustomData`; limita esos datos a lo necesario.

## Diseño

Cada token usa serialización compacta JOSE anidada:

1. Claims JWT JSON firmados como JWS `EdDSA`.
2. Ese JWS se cifra como JWE `alg=dir`, `enc=A256GCM`, con `cty=JWT`.

La salida tiene cinco segmentos JWE. Una biblioteca JOSE compatible con JWE/JWS puede descifrar el token, verificar la firma y leer los claims si recibe las claves y los algoritmos acordados. Compartir una clave de cifrado permite leer los claims; únicamente compartir la clave privada Ed25519 permite emitir tokens válidos. Los consumidores deberían recibir solo la clave pública de firma.

El token es opaco para el navegador, pero quien tenga la clave JWE puede descifrarlo. Protege las claves como secretos de producción. No pongas claves privadas ni claves AES en el frontend.

## Claims

| Campo | Uso |
| --- | --- |
| `iss` | Emisor configurado en Goxis |
| `sub` | Identificador del usuario |
| `aud` | Lista de servicios destinatarios |
| `sid` | Identificador de sesión |
| `jti` | Identificador aleatorio del token |
| `fid` | Familia de rotación del refresh |
| `token_use` | `access` o `refresh` |
| `iat`, `exp` | Emisión y expiración, en segundos Unix |
| `email`, `custom_data` | Datos opcionales de `JWTManager` / `IssueOptions` |
| `roles`, `permissions` | Snapshot opcional para autorización |

Goxis no agrega IP ni User-Agent automáticamente. `JWTManager` puede serializar `Email` y `CustomData`; el `Manager` los recibe desde `IssueOptions`. Incluye solo los campos necesarios y evita secretos o datos personales que no deban quedar dentro del token. Los roles y permisos incluidos son una fotografía emitida en ese momento: si cambian antes de vencer el access token, el servicio debe consultar su fuente de autorización o esperar su expiración.

## Duraciones predeterminadas

Si no se especifican `AccessTTL` y `RefreshTTL`, `Level` utiliza las duraciones alineadas con los niveles existentes en Goxis/GoKit:

| Nivel | Access | Refresh |
| --- | ---: | ---: |
| `security.Low` | 24 horas | 30 días |
| `security.Medium` (también `security.Default`) | 1 hora | 7 días |
| `security.High` | 15 minutos | 24 horas |
| `security.Critical` | 5 minutos | 12 horas |

Para producción suele convenir elegir explícitamente un nivel y evaluar la duración de access según el riesgo y la experiencia esperada.

## Crear claves

Genera claves por ambiente mediante un gestor de secretos o una herramienta segura. Este ejemplo muestra el formato Go; no uses una clave fija como la siguiente en producción:

```go
signingPublic, signingPrivate, err := ed25519.GenerateKey(rand.Reader)
if err != nil {
    return err
}
encryptionKey := make([]byte, 32) // AES-256
if _, err := rand.Read(encryptionKey); err != nil {
    return err
}
```

Guarda las claves privadas y AES fuera del repositorio. No compartas el mismo par de claves entre ambientes. La clave de firma es de 64 bytes privada / 32 bytes pública; cada clave AES debe tener exactamente 32 bytes.

## Configurar el emisor y emitir tokens

El emisor necesita una clave privada, claves de cifrado y un `RefreshStore`. El almacén de memoria es solo para desarrollo local y procesos únicos:

```go
package auth

import (
    "crypto/ed25519"

    "github.com/AndresGT/Goxis/security"
    "github.com/AndresGT/Goxis/security/token"
)

func newTokenManager(private ed25519.PrivateKey, aesKey []byte) (*token.Manager, error) {
    return token.New(token.Config{
        Issuer: "https://auth.example.com",
        Audience: []string{"goxis-api"},
        Level: security.High,
        SigningKeyID: "sign-2026-01",
        SigningKey: private,
        EncryptionKeyID: "encrypt-2026-01",
        EncryptionKeys: map[string][]byte{"encrypt-2026-01": aesKey},
        Store: token.NewMemoryStore(), // Redis/SQL en despliegues reales
    })
}

func login(manager *token.Manager, userID string) (token.Pair, error) {
    return manager.Issue(token.IssueOptions{
        UserID: userID,
        Roles: []string{"user"},
        Permissions: []string{"orders:read"},
    })
}
```

`Issue` genera un `sid` si no se proporciona y crea access y refresh tokens vinculados a una familia. Devuelve el access TTL en `expires_in`. El refresh inicial se registra antes de devolver la pareja; si el almacén falla, la emisión falla.

## Validar en handlers y servicios

Cada proceso que valide debe tener la clave AES de descifrado, la clave pública Ed25519 del emisor, y el mismo `Issuer`/`Audience` esperado. No necesita la clave privada ni conexión al almacenamiento para validar access tokens.

```go
validator, err := token.New(token.Config{
    Issuer: "https://auth.example.com",
    Audience: []string{"goxis-api"},
    VerificationKeys: map[string]ed25519.PublicKey{
        "sign-2026-01": signingPublic,
    },
    EncryptionKeys: map[string][]byte{
        "encrypt-2026-01": aesKey,
    },
})
if err != nil {
    return err
}

claims, err := validator.Validate(bearerToken, token.AccessToken)
if err != nil {
    // Responder 401 sin exponer detalles criptográficos al cliente.
    return err
}
userID := claims.Subject
roles := claims.Roles
```

`Validate` comprueba la estructura JOSE, algoritmos permitidos, `kid`, autenticidad de cifrado, firma, emisor, audiencia, tipo, fechas y expiración. No consulta el `RefreshStore`. Eso permite validar access tokens sin estado compartido. Una validación correcta no significa que el usuario siga activo en la base de datos; esa política pertenece al servicio.

Para extraer un dato puntual como `tenant_id` de `CustomData` desde la capa de servicios, valida primero el token y comprueba su tipo. El ejemplo completo está en [`examples/servicestokendemo`](../../examples/servicestokendemo):

```go
claims, err := manager.Validate(rawToken, token.AccessToken)
if err != nil { return err }
tenantID, ok := claims.CustomData["tenant_id"].(string)
if !ok || tenantID == "" { return errors.New("tenant_id no válido") }
```

La API de bajo nivel (`Manager`) permite que el servicio validador tenga solo la clave pública Ed25519 y la clave AES de descifrado; así no recibe la clave privada de firma. `IssueOptions` permite incluir `Email` y `CustomData` al emitir. El ejemplo completo con roles separados de emisor/validador está en [`examples/servicestokendemo`](../../examples/servicestokendemo).

## Renovar y revocar

La renovación siempre consume el refresh anterior y emite otro. Dos solicitudes simultáneas no deben poder renovar el mismo token: la operación `Rotate` del almacén es atómica. Si reaparece un refresh ya consumido, el almacén detecta reutilización y revoca toda su familia.

```go
pair, err := manager.Refresh(refreshToken)
if err != nil {
    // Tratar como refresh inválido y pedir autenticación de nuevo.
}

if err := manager.RevokeSession(sessionID); err != nil {
    // No indicar al cliente que la revocación quedó aplicada si el almacén falló.
}
if err := manager.RevokeUser(userID); err != nil {
    // Revoca los refresh del usuario en todas sus sesiones.
}
```

La revocación del almacén bloquea renovaciones futuras; los access ya emitidos siguen válidos hasta `exp` si los servicios solo verifican criptografía localmente. Para revocación inmediata de access, usa access TTL corto y agrega una consulta de sesión/introspección compartida a la autorización de rutas sensibles.

## Almacenamiento de refresh

El `RefreshStore` guarda únicamente el digest SHA-256 del `jti`, la familia, usuario, sesión, expiración y estado. Nunca almacena el token bearer. Escoge un único backend compartido por todos los nodos de una instalación; no hay fallback automático entre Redis, SQL y memoria.

### Memoria (solo desarrollo)

```go
Store: token.NewMemoryStore(),
```

Los datos desaparecen al reiniciar y no se comparten entre instancias.

### Redis (recomendado)

`NewRedisStore` recibe un adaptador `Eval` para evitar fijar el proyecto a un cliente Redis concreto. Ejemplo con un cliente cuya llamada es `Eval(ctx, script, keys, args...).Result()`:

```go
redisStore, err := token.NewRedisStore(
    func(ctx context.Context, script string, keys []string, args ...any) (any, error) {
        return redisClient.Eval(ctx, script, keys, args...).Result()
    },
    "goxis:production:security:refresh",
)
if err != nil { return err }

manager, err := token.New(token.Config{
    // Issuer, claves y nivel...
    Store: redisStore,
})
```

El cliente Redis se importa/configura en la aplicación; Goxis no añade una dependencia Redis obligatoria. Las operaciones usan Lua para hacer atómica la rotación. El adaptador inicial mantiene registros en un hash Redis y la revocación recorre sus registros; planifica compactación/limpieza o segmentación conforme crezca el volumen. Configura persistencia AOF/RDB según tu objetivo de recuperación, política `noeviction`, TLS/red privada, autenticación y monitoreo. Si Redis no está disponible, las operaciones de emisión/renovación/revocación fallan; no continúan en memoria.

### PostgreSQL o MySQL

`SQLStore` usa `database/sql`, así que la aplicación instala el driver que ya utilice. Ejecuta su DDL una vez en la migración de tu proyecto; el paquete no migra la base automáticamente:

```go
store, err := token.NewSQLStore(db, token.Postgres) // o token.MySQL
if err != nil { return err }
if _, err := db.Exec(store.SchemaSQL()); err != nil { return err }
manager, err := token.New(token.Config{ /* claves, issuer, level */ Store: store })
```

Administra cambios de esquema con tus migraciones habituales. Restringe el acceso de la cuenta SQL a esta tabla y usa TLS según el despliegue.

## Rotación de claves

Los headers contienen `kid` en JWS y JWE. Para rotar sin invalidar de inmediato los tokens existentes:

1. Añade la nueva clave pública de firma y la nueva clave AES a todos los validadores.
2. Configura el emisor con los nuevos IDs como activos y emite tokens nuevos.
3. Conserva claves anteriores mientras puedan existir tokens emitidos con ellas (al menos el máximo TTL aplicable y margen de reloj).
4. Retira las claves antiguas cuando hayan expirado todos esos tokens.

La rotación de la clave AES requiere que los validadores mantengan las claves previas durante esa ventana porque cada JWE identifica su `kid`. La rotación de signing key usa el `kid` del JWS interno.

## Recomendaciones operativas

- Envía tokens solo sobre HTTPS y no los escribas en logs, URLs ni mensajes de error.
- Mantén las claves de firma privadas exclusivamente en el emisor; comparte claves públicas a validadores.
- La clave AES sí permite descifrar: compártela únicamente con servicios autorizados para leer claims.
- Valida `aud` por servicio y usa una audiencia distinta cuando los límites de confianza lo requieran.
- Para navegador, evalúa cookies `HttpOnly`, `Secure`, `SameSite` y protección CSRF; cifrar el token no evita XSS ni robo de bearer tokens.
- Usa el refresh una sola vez y reemplázalo en el cliente en cada renovación.
- Usa Redis/SQL compartido en múltiples réplicas. No uses `MemoryStore` en despliegues distribuidos.

## Interoperabilidad

Formatos y algoritmos usados: JWS compact `EdDSA` (Ed25519) dentro de JWE compact `dir` + `A256GCM`. Un servicio escrito en otro lenguaje puede usar una biblioteca JOSE que implemente estos estándares y configurar las claves según sus requisitos. La serialización es JOSE estándar; los nombres `sid`, `fid` y `token_use` son claims de aplicación. La validación de audiencia, emisor, fechas y tipo debe conservar la misma política que Goxis.

Referencias: [RFC 7516 (JWE)](https://www.rfc-editor.org/rfc/rfc7516.html), [RFC 7518 (A256GCM)](https://www.rfc-editor.org/rfc/rfc7518.html), [RFC 8037 (EdDSA en JOSE)](https://www.rfc-editor.org/rfc/rfc8037.html) y [RFC 9700 (rotación y reutilización de refresh tokens)](https://www.rfc-editor.org/rfc/rfc9700.html).
# Sesiones

Además de access/refresh tokens, Goxis proporciona `SessionManager` para sesiones revocables, límites concurrentes e inactividad. Consulta [SESSIONS.md](SESSIONS.md) para el flujo y la interfaz `SessionStore`.
