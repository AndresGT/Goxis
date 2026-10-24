# `security`

Paquete común de políticas de seguridad y errores para los módulos de Goxis. Los subpaquetes son:

| Paquete | Propósito | Guía |
| --- | --- | --- |
| `security/crypto` | Hash de contraseñas, AES-GCM, secretos aleatorios | [README](crypto/README.md) |
| `security/token` | Access/refresh cifrados, refresh store y sesiones | [README de tokens](token/README.md), [sesiones](token/SESSIONS.md) |
| `security/audit` | Eventos, filtros, memoria y exportación | [README](audit/README.md) |

## Niveles de seguridad

`Level` centraliza los tiempos de access/refresh, límite de sesiones, expiración de sesión y defaults de lockout. `Default` y un valor desconocido usan los defaults de `Medium`:

```go
defaults := security.High.GetDefaults()
accessTTL := defaults.AccessTokenDuration
sessionTTL := defaults.SessionTimeout
maxSessions := defaults.MaxConcurrentSessions
```

| Nivel | Access | Refresh | Sesiones simultáneas | Idle timeout |
| --- | ---: | ---: | ---: | ---: |
| `Low` | 24 h | 30 días | 5 | 24 h |
| `Medium` / `Default` | 1 h | 7 días | 3 | 30 min |
| `High` | 15 min | 24 h | 2 | 15 min |
| `Critical` | 5 min | 12 h | 1 | 5 min |

Son valores de inicio; configura TTL y límites según el riesgo y carga de tu aplicación. `SecurityDefaults.BcryptCost` es un parámetro disponible para configurar bcrypt; no reemplaza la configuración explícita de `security/crypto`.

Puedes derivar una configuración de hashing del nivel elegido y aplicarla globalmente una vez durante el arranque:

```go
import (
    "github.com/AndresGT/Goxis/security"
    "github.com/AndresGT/Goxis/security/crypto"
)

func configurePasswordHashing() error {
    defaults := security.Critical.GetDefaults()
    return crypto.ConfigureDefaultHasher(crypto.HasherConfig{
        Algorithm: crypto.AlgorithmBcrypt,
        BcryptCost: defaults.BcryptCost,
    })
}
```

Para Argon2id, normalmente se configura memoria/pasadas directamente con `crypto.HasherConfig`; sus parámetros son independientes del campo legacy `BcryptCost`.

## Errores compartidos

Usa `errors.Is` para comparar los errores de dominio, por ejemplo `security.ErrAuthenticationFailed`, `security.ErrPermissionDenied`, `security.ErrTokenInvalid`, `security.ErrSessionExpired` y `security.ErrRateLimitExceeded`. Los paquetes especializados (`token`, `crypto`, `app`) también exponen errores más específicos.
