# Sesiones

`SessionManager` administra sesiones con expiración absoluta, inactividad, límite de sesiones simultáneas y revocación individual o global. Al crear `SessionConfig`, se puede inyectar cualquier `SessionStore`; si no se proporciona, usa `MemorySessionStore` (volátil y de un solo proceso).

## Configuración global

Los helpers `CreateQuickSession`, `ValidateQuickSession`, `RevokeQuickSession` y otros usan un único manager global. Configúralo una vez al iniciar el proceso:

```go
if err := token.InitSession(token.SessionConfig{
    SecurityLevel: security.LevelHigh,
    SessionTimeout: 8 * time.Hour,
    IdleTimeout: 15 * time.Minute,
    MaxConcurrentSessions: 2,
    Store: token.NewMemorySessionStore(),
}); err != nil { return err }

sessionID, err := token.CreateQuickSession(token.SessionInfo{UserID: userID})
```

El manager global predeterminado usa memoria y un máximo de cinco sesiones para facilitar desarrollo. Configúralo explícitamente antes de usar los helpers.

## Configuración aislada y estricta

Usa una instancia propia si necesitas políticas distintas por servicio/tenant o quieres evitar estado global. El nivel `Critical` parte de una sesión absoluta de 2 horas, idle timeout de 5 minutos y una sesión concurrente; los valores pueden endurecerse en la configuración explícita:

```go
manager := token.NewSessionManager(token.SessionConfig{
    SecurityLevel: security.LevelCritical,
    SessionTimeout: 90 * time.Minute,
    IdleTimeout: 3 * time.Minute,
    MaxConcurrentSessions: 1,
    Store: token.NewMemorySessionStore(), // reemplazar por un SessionStore compartido en producción
})
id, err := manager.CreateSession(token.SessionInfo{UserID: user.ID, IPAddress: ip, UserAgent: ua})
session, err := manager.ValidateSession(id) // actualiza actividad; úsalo en cada request autenticado
err = manager.RevokeSession(id, "logout")
err = manager.RevokeAllUserSessions(user.ID, "password_changed")
```

`SessionStore` expone `Save`, `Get`, `GetByUserID`, `Delete`, `DeleteByUserID` y `CleanExpired`. Un backend distribuido debe hacer estas operaciones de forma segura entre instancias y devolver copias o valores aislados. Los helpers `InitSession`, `CreateQuickSession`, `ValidateQuickSession` y relacionados usan un manager global; para servidores concurrentes/multi-tenant se recomienda crear e inyectar una instancia propia.
