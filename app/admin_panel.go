package goxis

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	goxislog "github.com/AndresGT/Goxis/log"
	"github.com/AndresGT/Goxis/security/crypto"
	"github.com/AndresGT/Goxis/security/token"
)

//go:embed admin_panel.html
var adminPanelDocument string

//go:embed admin_assets/*
var adminPanelAssets embed.FS

const defaultAdminPanelPath = "/_goxis/admin"
const maxAdminPanelLogEntries = 10000
const maxAdminRequestHistory = 5000

// AdminPanelConfig configures the optional in-process admin dashboard.
type AdminPanelConfig struct {
	Path              string            // Base path; defaults to /_goxis/admin.
	MaxLogEntries     int               // Maximum recent formatted lines retained; defaults to 500.
	MaxMetricSamples  int               // Maximum recent request samples retained; defaults to 2048.
	AdminUsername     string            // Login name; no default account is created.
	AdminPasswordHash string            // Password hash produced by security/crypto.HashPassword.
	TokenManager      *token.JWTManager // Stable security/token manager used to sign the session cookie.
	SessionTTL        time.Duration     // Cookie session duration; defaults to 15 minutes.
	MaxLoginAttempts  int               // Failed logins allowed per client IP; defaults to 5.
	LoginLockout      time.Duration     // Failure window and lockout duration; defaults to 15 minutes.
	CookieName        string            // Defaults to goxis_admin_session.
	SecureCookie      bool              // Force Secure; set true when TLS terminates at a trusted reverse proxy.
	LogFilePath       string            // Persistent rotating log path; defaults to logs/goxis-admin.log.
	MaxLogFileBytes   int64             // Defaults to 10 MiB per file.
	MaxLogFiles       int               // Number of rotated files to keep; defaults to 5.
}

// WithAdminPanel mounts a dashboard on the same listener as the App. Its data
// endpoints require a session cookie issued after validating the configured
// username and password. AdminPasswordHash should be generated with
// security/crypto.HashPassword, and TokenManager must use a stable secret.
func WithAdminPanel(config AdminPanelConfig) Option {
	return func(app *App) {
		if app.adminPanel != nil {
			app.startupErr = errors.Join(app.startupErr, errors.New("goxis: admin panel is already configured"))
			return
		}
		base := cleanPath(strings.TrimSpace(config.Path))
		if base == "/" {
			base = defaultAdminPanelPath
		}
		if !validAdminBasePath(base) {
			app.startupErr = errors.Join(app.startupErr, errors.New("goxis: admin panel path must contain only letters, numbers, '/', '-' and '_'"))
			return
		}
		if strings.TrimSpace(config.AdminUsername) == "" || config.AdminPasswordHash == "" || config.TokenManager == nil {
			app.startupErr = errors.Join(app.startupErr, errors.New("goxis: admin panel requires AdminUsername, AdminPasswordHash, and TokenManager"))
			return
		}
		if _, err := crypto.DetectAlgorithm(config.AdminPasswordHash); err != nil {
			app.startupErr = errors.Join(app.startupErr, fmt.Errorf("goxis: invalid admin password hash: %w", err))
			return
		}
		if config.SessionTTL <= 0 {
			config.SessionTTL = 15 * time.Minute
		}
		if config.SessionTTL > 24*time.Hour {
			config.SessionTTL = 24 * time.Hour
		}
		if config.MaxLoginAttempts <= 0 {
			config.MaxLoginAttempts = 5
		}
		if config.LoginLockout <= 0 {
			config.LoginLockout = 15 * time.Minute
		}
		if config.CookieName == "" {
			config.CookieName = "goxis_admin_session"
		}
		if strings.ContainsAny(config.CookieName, " ;,=\t\r\n") {
			app.startupErr = errors.Join(app.startupErr, errors.New("goxis: invalid admin session cookie name"))
			return
		}
		if config.MaxLogEntries <= 0 {
			config.MaxLogEntries = 500
		}
		if config.MaxLogEntries > maxAdminPanelLogEntries {
			config.MaxLogEntries = maxAdminPanelLogEntries
		}
		if config.MaxMetricSamples <= 0 {
			config.MaxMetricSamples = defaultMetricSamples
		}
		if config.MaxMetricSamples > maxMetricSamples {
			config.MaxMetricSamples = maxMetricSamples
		}
		fileLogger, recent, err := openAdminLogFile(config.LogFilePath, config.MaxLogFileBytes, config.MaxLogFiles)
		if err != nil {
			app.startupErr = errors.Join(app.startupErr, fmt.Errorf("goxis: open admin log file: %w", err))
			return
		}
		buffer := goxislog.NewRingBuffer(config.MaxLogEntries)
		for _, line := range recent {
			_, _ = io.WriteString(buffer, line+"\n")
		}
		panel := &adminPanel{
			app: app, base: base, logs: buffer, subscribers: make(map[uint64]chan adminEvent),
			adminUsername: strings.TrimSpace(config.AdminUsername), passwordHash: config.AdminPasswordHash,
			tokenManager: config.TokenManager, sessionTTL: config.SessionTTL, cookieName: config.CookieName,
			secureCookie: config.SecureCookie, fileLogger: fileLogger,
			maxLoginAttempts: config.MaxLoginAttempts, loginLockout: config.LoginLockout,
			loginAttempts: make(map[string]adminLoginAttempt),
		}
		buffer.SetOnLine(func(line string) { panel.publish("log", map[string]string{"line": line}) })
		panel.detachLogWriter = goxislog.GetDefault().AddWriter(io.MultiWriter(buffer, fileLogger))
		app.adminPanel = panel
		app.metrics = newRequestMetrics(config.MaxMetricSamples)
		app.metrics.onUpdate = func() { panel.publish("metrics", app.metrics.snapshot()) }
	}
}

func validAdminBasePath(path string) bool {
	if path == "/" {
		return false
	}
	for _, r := range path {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '/' || r == '-' || r == '_' {
			continue
		}
		return false
	}
	return true
}

type adminPanel struct {
	app              *App
	base             string
	logs             *goxislog.RingBuffer
	mu               sync.Mutex
	subscribers      map[uint64]chan adminEvent
	nextID           uint64
	adminUsername    string
	passwordHash     string
	tokenManager     *token.JWTManager
	sessionTTL       time.Duration
	cookieName       string
	secureCookie     bool
	fileLogger       *adminLogFile
	detachLogWriter  func()
	closeOnce        sync.Once
	loginMu          sync.Mutex
	loginAttempts    map[string]adminLoginAttempt
	maxLoginAttempts int
	loginLockout     time.Duration
}

type adminLoginAttempt struct {
	count       int
	windowStart time.Time
	lockedUntil time.Time
}

func (p *adminPanel) close() error {
	var err error
	p.closeOnce.Do(func() {
		if p.detachLogWriter != nil {
			p.detachLogWriter()
		}
		if p.fileLogger != nil {
			err = p.fileLogger.Close()
		}
	})
	return err
}

type adminEvent struct {
	name string
	data []byte
}

func (p *adminPanel) publish(name string, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		return
	}
	event := adminEvent{name: name, data: data}
	p.mu.Lock()
	for _, subscriber := range p.subscribers {
		select {
		case subscriber <- event:
		default:
			select {
			case <-subscriber:
			default:
			}
			select {
			case subscriber <- event:
			default:
			}
		}
	}
	p.mu.Unlock()
}

func (p *adminPanel) subscribe() (<-chan adminEvent, func()) {
	p.mu.Lock()
	p.nextID++
	id := p.nextID
	channel := make(chan adminEvent, 128)
	p.subscribers[id] = channel
	p.mu.Unlock()
	var once sync.Once
	return channel, func() { once.Do(func() { p.mu.Lock(); delete(p.subscribers, id); close(channel); p.mu.Unlock() }) }
}

type adminRoute struct {
	Method        string   `json:"method"`
	Path          string   `json:"path"`
	Group         string   `json:"group"`
	Protected     bool     `json:"protected"`
	Roles         []string `json:"roles,omitempty"`
	AnyRole       []string `json:"any_roles,omitempty"`
	Permissions   []string `json:"permissions,omitempty"`
	RateLimit     int      `json:"rate_limit_per_minute,omitempty"`
	MaxConcurrent int      `json:"max_concurrent,omitempty"`
	QueueLimit    int      `json:"queue_limit,omitempty"`
}

func (p *adminPanel) matches(path string) bool {
	return path == p.base || path == p.base+"/" || strings.HasPrefix(path, p.base+"/")
}

func (p *adminPanel) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, p.base+"/assets/") {
		p.serveAsset(w, r)
		return
	}
	if r.URL.Path == p.base+"/login" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed)
			return
		}
		p.login(w, r)
		return
	}
	if r.URL.Path == p.base+"/logout" {
		if r.Method != http.MethodPost {
			w.Header().Set("Allow", http.MethodPost)
			writeError(w, http.StatusMethodNotAllowed)
			return
		}
		p.logout(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == p.base || r.URL.Path == p.base+"/" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		document := strings.ReplaceAll(adminPanelDocument, "__GOXIS_ADMIN_BASE__", p.base)
		authenticated := "false"
		if p.authorizeAdmin(r) == 0 {
			authenticated = "true"
		}
		document = strings.ReplaceAll(document, "__GOXIS_ADMIN_AUTHENTICATED__", authenticated)
		_, _ = w.Write([]byte(document))
		return
	}
	if r.URL.Path != p.base+"/api/logs" && r.URL.Path != p.base+"/api/routes" && r.URL.Path != p.base+"/api/metrics" && r.URL.Path != p.base+"/api/events" {
		http.NotFound(w, r)
		return
	}
	if status := p.authorizeAdmin(r); status != 0 {
		writeError(w, status)
		return
	}
	if r.URL.Path == p.base+"/api/events" {
		p.serveEvents(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	encoder := json.NewEncoder(w)
	if r.URL.Path == p.base+"/api/logs" {
		_ = encoder.Encode(map[string]any{"logs": p.logSnapshot()})
	} else if r.URL.Path == p.base+"/api/routes" {
		_ = encoder.Encode(map[string]any{"routes": p.routes()})
	} else {
		_ = encoder.Encode(p.app.metrics.snapshot())
	}
}

func (p *adminPanel) serveAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, p.base+"/assets/")
	if name != "goxis-logo.jpeg" && name != "goxis-mascot.jpeg" {
		http.NotFound(w, r)
		return
	}
	data, err := adminPanelAssets.ReadFile("admin_assets/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(data)
}

type adminLoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (p *adminPanel) login(w http.ResponseWriter, r *http.Request) {
	clientIP := adminClientIP(r)
	if retryAfter := p.loginRetryAfter(clientIP, time.Now()); retryAfter > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds()+0.999)))
		writeError(w, http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var credentials adminLoginRequest
	if err := json.NewDecoder(r.Body).Decode(&credentials); err != nil {
		writeError(w, http.StatusBadRequest)
		return
	}
	usernameOK := subtle.ConstantTimeCompare([]byte(credentials.Username), []byte(p.adminUsername)) == 1
	passwordOK, err := crypto.VerifyPassword(credentials.Password, p.passwordHash)
	if !usernameOK || err != nil || !passwordOK {
		if p.recordFailedLogin(clientIP, time.Now()) {
			w.Header().Set("Retry-After", fmt.Sprintf("%d", int(p.loginLockout.Seconds()+0.999)))
			writeError(w, http.StatusTooManyRequests)
			return
		}
		writeError(w, http.StatusUnauthorized)
		return
	}
	p.clearLoginAttempts(clientIP)
	session, err := p.tokenManager.GenerateAccessToken(token.Claims{UserID: "goxis-admin-panel", Roles: []string{"admin"}})
	if err != nil {
		writeError(w, http.StatusInternalServerError)
		return
	}
	now := time.Now()
	http.SetCookie(w, &http.Cookie{
		Name: p.cookieName, Value: session, Path: p.base + "/", HttpOnly: true,
		Secure: p.secureCookie || r.TLS != nil, SameSite: http.SameSiteStrictMode,
		Expires: now.Add(p.sessionTTL), MaxAge: int(p.sessionTTL.Seconds()),
	})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"authenticated": true, "expires_in": int64(p.sessionTTL.Seconds())})
}

func adminClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		if ip := net.ParseIP(host); ip != nil {
			return ip.String()
		}
	}
	if ip := net.ParseIP(r.RemoteAddr); ip != nil {
		return ip.String()
	}
	return "unknown"
}

func (p *adminPanel) loginRetryAfter(clientIP string, now time.Time) time.Duration {
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	attempt, ok := p.loginAttempts[clientIP]
	if !ok {
		return 0
	}
	if !attempt.lockedUntil.IsZero() && !now.Before(attempt.lockedUntil) {
		delete(p.loginAttempts, clientIP)
		return 0
	}
	if !attempt.lockedUntil.IsZero() {
		return attempt.lockedUntil.Sub(now)
	}
	if now.Sub(attempt.windowStart) >= p.loginLockout {
		delete(p.loginAttempts, clientIP)
	}
	return 0
}

func (p *adminPanel) recordFailedLogin(clientIP string, now time.Time) bool {
	p.loginMu.Lock()
	defer p.loginMu.Unlock()
	if len(p.loginAttempts) >= 4096 {
		for ip, attempt := range p.loginAttempts {
			if !now.Before(attempt.lockedUntil) {
				delete(p.loginAttempts, ip)
			}
		}
		if len(p.loginAttempts) >= 4096 {
			return true
		}
	}
	attempt := p.loginAttempts[clientIP]
	if attempt.windowStart.IsZero() || now.Sub(attempt.windowStart) >= p.loginLockout {
		attempt = adminLoginAttempt{windowStart: now}
	}
	attempt.count++
	if attempt.count >= p.maxLoginAttempts {
		attempt.lockedUntil = now.Add(p.loginLockout)
		p.loginAttempts[clientIP] = attempt
		return true
	}
	p.loginAttempts[clientIP] = attempt
	return false
}

func (p *adminPanel) clearLoginAttempts(clientIP string) {
	p.loginMu.Lock()
	delete(p.loginAttempts, clientIP)
	p.loginMu.Unlock()
}

func (p *adminPanel) logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: p.cookieName, Value: "", Path: p.base + "/", HttpOnly: true,
		Secure: p.secureCookie || r.TLS != nil, SameSite: http.SameSiteStrictMode,
		Expires: time.Unix(1, 0), MaxAge: -1,
	})
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusNoContent)
}

func (p *adminPanel) authorizeAdmin(r *http.Request) int {
	cookie, err := r.Cookie(p.cookieName)
	if err != nil {
		return http.StatusUnauthorized
	}
	claims, err := p.tokenManager.ValidateAccessToken(cookie.Value)
	if err != nil {
		return http.StatusUnauthorized
	}
	for _, role := range claims.Roles {
		if role == "admin" {
			return 0
		}
	}
	return http.StatusForbidden
}

func (p *adminPanel) serveEvents(w http.ResponseWriter, r *http.Request) {
	controller := http.NewResponseController(w)
	_ = controller.SetWriteDeadline(time.Time{})
	w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache, no-transform")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, http.StatusInternalServerError)
		return
	}
	events, unsubscribe := p.subscribe()
	defer unsubscribe()
	w.WriteHeader(http.StatusOK)
	_ = writeSSE(w, "metrics", p.app.metrics.snapshot())
	_ = writeSSE(w, "routes", map[string]any{"routes": p.routes()})
	_ = writeSSE(w, "logs", map[string]any{"logs": p.logSnapshot()})
	_ = writeSSE(w, "requests", map[string]any{"requests": p.app.metrics.recentRequests(maxAdminRequestHistory)})
	_ = writeSSE(w, "queues", p.queueSnapshot())
	_ = writeSSE(w, "performance", snapshotRuntime(p.app))
	flusher.Flush()
	keepAlive := time.NewTicker(20 * time.Second)
	defer keepAlive.Stop()
	performanceTicker := time.NewTicker(5 * time.Second)
	defer performanceTicker.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepAlive.C:
			if p.authorizeAdmin(r) != 0 {
				return
			}
			if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case <-performanceTicker.C:
			if p.authorizeAdmin(r) != 0 {
				return
			}
			if err := writeSSE(w, "performance", snapshotRuntime(p.app)); err != nil {
				return
			}
			flusher.Flush()
		case event := <-events:
			if p.authorizeAdmin(r) != 0 {
				return
			}
			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.name, event.data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (p *adminPanel) logSnapshot() []string {
	lines := p.logs.Snapshot()
	filtered := make([]string, 0, len(lines))
	adminPath := `"` + p.base
	for _, line := range lines {
		if strings.HasPrefix(line, "[GOXIS] ") && strings.Contains(line, adminPath) {
			continue
		}
		filtered = append(filtered, line)
	}
	return filtered
}

func writeSSE(w http.ResponseWriter, name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", name, data)
	return err
}

func (p *adminPanel) routes() []adminRoute {
	p.app.mu.RLock()
	defer p.app.mu.RUnlock()
	routes := make([]adminRoute, 0, len(p.app.routes))
	for _, entry := range p.app.routes {
		routes = append(routes, adminRoute{
			Method: entry.method, Path: entry.path, Group: entry.group, Protected: entry.protected,
			Roles: append([]string(nil), entry.policy.Roles...), AnyRole: append([]string(nil), entry.policy.AnyRole...),
			Permissions: append([]string(nil), entry.policy.Permissions...), RateLimit: entry.rateLimit,
			MaxConcurrent: entry.maxConcurrent, QueueLimit: entry.queueLimit,
		})
	}
	return routes
}

func (p *adminPanel) queueSnapshot() queuePanelSnapshot {
	snapshot := queuePanelSnapshot{Routes: make([]queueRouteStatus, 0)}
	p.app.mu.RLock()
	for _, entry := range p.app.routes {
		if entry.queue == nil {
			continue
		}
		status := entry.queue.snapshot(entry.method, entry.path, entry.group, entry.maxConcurrent, entry.queueLimit)
		snapshot.Running += status.Running
		snapshot.Waiting += status.Waiting
		snapshot.Rejected += status.Rejected
		snapshot.Canceled += status.Canceled
		snapshot.Failures = append(snapshot.Failures, entry.queue.failureSnapshot()...)
		snapshot.Routes = append(snapshot.Routes, status)
	}
	p.app.mu.RUnlock()
	sort.Slice(snapshot.Failures, func(i, j int) bool {
		return snapshot.Failures[i].Timestamp.After(snapshot.Failures[j].Timestamp)
	})
	if len(snapshot.Failures) > 500 {
		snapshot.Failures = snapshot.Failures[:500]
	}
	return snapshot
}

func (p *adminPanel) publishQueueSnapshot() {
	p.publish("queues", p.queueSnapshot())
}

func (p *adminPanel) publishQueueRoute(entry *routeEntry) {
	if entry == nil || entry.queue == nil {
		return
	}
	status := entry.queue.snapshot(entry.method, entry.path, entry.group, entry.maxConcurrent, entry.queueLimit)
	p.publish("queue_route", status)
}
