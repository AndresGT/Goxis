package goxis

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Common HTTP method names used when registering routes.
const (
	GET     = http.MethodGet
	POST    = http.MethodPost
	PUT     = http.MethodPut
	PATCH   = http.MethodPatch
	DELETE  = http.MethodDelete
	OPTIONS = http.MethodOptions
	HEAD    = http.MethodHead
)

var (
	ErrNotFound                 = errors.New("goxis: route not found")
	ErrMethodNotAllowed         = errors.New("goxis: method not allowed")
	ErrUnauthenticated          = errors.New("goxis: unauthenticated")
	ErrForbidden                = errors.New("goxis: forbidden")
	ErrAccessControlUnavailable = errors.New("goxis: access control is not configured")
	ErrRateLimitExceeded        = errors.New("goxis: rate limit exceeded")
	ErrQueueFull                = errors.New("goxis: request queue is full")
	ErrInvalidRoute             = errors.New("goxis: invalid route")
	ErrDuplicateRoute           = errors.New("goxis: duplicate route")
)

// Handler processes a request using Goxis' framework-owned Context.
type Handler func(*Context) error

// Middleware wraps a Goxis handler. Middleware is applied in registration
// order: the first middleware runs first on the request and last on the reply.
type Middleware func(Handler) Handler

// Authorizer evaluates the policy inherited by a route from its groups.
// Authentication middleware can attach identity data to Context before this
// method is called.
type Authorizer interface {
	Authorize(ctx *Context, policy Policy) error
}

// IdentityAuthenticator validates request credentials and stores a trusted
// identity on Context before route rate limiting. Authorizers that implement
// it enable per-user limits without making the app depend on token packages.
type IdentityAuthenticator interface {
	Authenticate(ctx *Context) error
}

// Policy supports roles that must all match, an alternative role list where
// any match is sufficient, and permissions that must all be granted.
type Policy struct {
	Roles       []string
	AnyRole     []string
	Permissions []string
}

// Option configures an App.
type Option func(*App)

// WithAuthorizer sets the access control implementation used by protected routes.
func WithAuthorizer(authorizer Authorizer) Option {
	return func(app *App) { app.authorizer = authorizer }
}

// App is a Goxis application and its custom HTTP router.
type App struct {
	mu             sync.RWMutex
	routes         []routeEntry
	middleware     []Middleware
	httpMiddleware []func(http.Handler) http.Handler
	startupErr     error
	authorizer     Authorizer
	serverConfig   HTTPServerConfig
	adminPanel     *adminPanel
	metrics        *requestMetrics
}

// New creates an application.
func New(options ...Option) *App {
	app := &App{serverConfig: DefaultHTTPServerConfig()}
	for _, option := range options {
		if option != nil {
			option(app)
		}
	}
	return app
}

// Close releases resources owned by optional App components, including the
// admin panel's persistent log writer. Call it after the HTTP server stops.
func (app *App) Close() error {
	if app == nil {
		return nil
	}
	app.mu.RLock()
	admin := app.adminPanel
	app.mu.RUnlock()
	if admin != nil {
		return admin.close()
	}
	return nil
}

// RouteCount returns the number of routes registered on the application.
func (app *App) RouteCount() int {
	if app == nil {
		return 0
	}
	app.mu.RLock()
	defer app.mu.RUnlock()
	return len(app.routes)
}

// Use registers middleware for every route in the application.
func (app *App) Use(middleware ...Middleware) {
	app.mu.Lock()
	defer app.mu.Unlock()
	app.middleware = append(app.middleware, nonNilMiddleware(middleware)...)
}

// RegisterHTTPMiddleware registers an HTTP wrapper and records configuration
// errors so Run can reject the app before opening its listener.
func (app *App) RegisterHTTPMiddleware(middleware func(http.Handler) http.Handler, setupErr error) {
	if middleware == nil {
		return
	}
	app.mu.Lock()
	app.httpMiddleware = append(app.httpMiddleware, middleware)
	if setupErr != nil {
		if app.startupErr == nil {
			app.startupErr = setupErr
		} else {
			app.startupErr = errors.Join(app.startupErr, setupErr)
		}
	}
	app.mu.Unlock()
}

// Group creates a route group rooted at prefix.
func (app *App) Group(prefix string, options ...GroupOption) *Group {
	group := &Group{app: app, prefix: cleanPath(prefix)}
	applyGroupOptions(group, options)
	return group
}

// ServeHTTP lets App be used as an HTTP handler while keeping routing and
// request context APIs owned by Goxis.
func (app *App) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	request, _ = attachRequestID(request, writer)
	started := time.Now()
	recorder := &responseRecorder{ResponseWriter: writer}
	app.mu.RLock()
	metrics := app.metrics
	admin := app.adminPanel
	app.mu.RUnlock()
	isAdminRequest := admin != nil && admin.matches(request.URL.Path)
	if isAdminRequest {
		metrics = nil
	}
	if metrics != nil {
		metrics.begin()
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			if recorder.status == 0 {
				writeError(recorder, http.StatusInternalServerError)
			}
			if metrics != nil {
				detail := app.requestRecord(request, recorder.status, time.Since(started))
				metrics.finish(detail)
				if admin != nil {
					admin.publish("request", detail)
				}
			}
			if !isAdminRequest {
				logRequest(request, recorder.status, time.Since(started))
			}
			return
		}
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		if metrics != nil {
			detail := app.requestRecord(request, status, time.Since(started))
			metrics.finish(detail)
			if admin != nil {
				admin.publish("request", detail)
			}
		}
		if !isAdminRequest {
			logRequest(request, status, time.Since(started))
		}
	}()

	app.mu.RLock()
	middlewares := append([]func(http.Handler) http.Handler(nil), app.httpMiddleware...)
	app.mu.RUnlock()

	var handler http.Handler = http.HandlerFunc(app.serveRoutes)
	if admin != nil && admin.matches(request.URL.Path) {
		handler = admin
	}
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	handler.ServeHTTP(recorder, request)
}

func (app *App) serveRoutes(writer http.ResponseWriter, request *http.Request) {
	path := cleanPath(request.URL.Path)
	app.mu.RLock()
	entry, params, pathFound := app.findRoute(path, request.Method)
	globalMiddleware := append([]Middleware(nil), app.middleware...)
	authorizer := app.authorizer
	admin := app.adminPanel
	allow := ""
	if pathFound && entry == nil {
		allow = allowedMethods(app.routes, path)
	}
	app.mu.RUnlock()

	if !pathFound {
		writeError(writer, http.StatusNotFound)
		return
	}
	if entry == nil {
		writer.Header().Set("Allow", allow)
		writeError(writer, http.StatusMethodNotAllowed)
		return
	}

	ctx := newContext(writer, request, params)
	hasPolicy := len(entry.policy.Roles) > 0 || len(entry.policy.AnyRole) > 0 || len(entry.policy.Permissions) > 0
	secured := entry.protected || hasPolicy
	var authenticationErr error
	if authenticator, ok := authorizer.(IdentityAuthenticator); ok && strings.TrimSpace(request.Header.Get("Authorization")) != "" {
		authenticationErr = authenticator.Authenticate(ctx)
		if !secured {
			authenticationErr = nil
		}
	}
	handler := entry.handler
	if entry.queue != nil {
		next := handler
		handler = func(ctx *Context) error {
			notifyQueue := func() {
				if admin != nil {
					admin.publishQueueRoute(entry)
				}
			}
			release, admission := entry.queue.acquire(ctx.Request.Context(), notifyQueue)
			if admission != queueAdmitted {
				reason := "queue_full"
				if admission == queueCanceled {
					reason = "request_canceled_while_waiting"
				}
				failure := queueFailure{
					Timestamp: time.Now(), Method: entry.method, Route: entry.method + " " + entry.path,
					Group: entry.group, Path: safeRequestURI(ctx.Request.URL), Reason: reason,
					ClientIP: remoteIP(ctx.Request.RemoteAddr), RequestID: ctx.RequestID(),
				}
				entry.queue.recordFailure(failure)
				if admin != nil {
					admin.publish("queue_failure", failure)
				}
				notifyQueue()
				if admission == queueRejected {
					ctx.Writer.Header().Set("Retry-After", "1")
					writeAppError(ctx.Writer, ErrQueueFull)
				}
				return nil
			}
			defer release()
			return next(ctx)
		}
	}
	if secured {
		next := handler
		handler = func(ctx *Context) error {
			if authenticationErr != nil {
				return authenticationErr
			}
			if authorizer == nil && hasPolicy {
				return ErrAccessControlUnavailable
			}
			if authorizer != nil {
				if err := authorizer.Authorize(ctx, entry.policy); err != nil {
					return err
				}
			}
			if entry.protected && !ctx.Authenticated() {
				return ErrUnauthenticated
			}
			return next(ctx)
		}
	}
	if entry.limiter != nil {
		next := handler
		handler = func(ctx *Context) error {
			key := ctx.Identity()
			if key != "" {
				key = "user:" + key
			} else {
				key = "ip:" + remoteIP(request.RemoteAddr)
			}
			if !entry.limiter.allow(key, time.Now()) {
				ctx.Writer.Header().Set("Retry-After", "60")
				writeAppError(ctx.Writer, ErrRateLimitExceeded)
				return nil
			}
			return next(ctx)
		}
	}

	middlewares := append(globalMiddleware, entry.middleware...)
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	if err := handler(ctx); err != nil && !ctx.Written() {
		writeAppError(writer, err)
	}
}

func (app *App) findRoute(path, method string) (*routeEntry, map[string]string, bool) {
	pathFound := false
	var best *routeEntry
	var bestParams map[string]string
	for i := range app.routes {
		params, matches := matchPath(app.routes[i].path, path)
		if !matches {
			continue
		}
		pathFound = true
		if app.routes[i].method == method || (method == http.MethodHead && app.routes[i].method == http.MethodGet) {
			if best == nil || routeMoreSpecific(app.routes[i].path, best.path) {
				best, bestParams = &app.routes[i], params
			}
		}
	}
	return best, bestParams, pathFound
}

func routeMoreSpecific(candidate, current string) bool {
	candidateParts, currentParts := splitPath(candidate), splitPath(current)
	for i := 0; i < len(candidateParts) && i < len(currentParts); i++ {
		candidateStatic := routeParamName(candidateParts[i]) == ""
		currentStatic := routeParamName(currentParts[i]) == ""
		if candidateStatic != currentStatic {
			return candidateStatic
		}
	}
	return false
}

func allowedMethods(routes []routeEntry, path string) string {
	methods := make([]string, 0)
	seen := make(map[string]bool)
	for _, route := range routes {
		if _, matches := matchPath(route.path, path); matches && !seen[route.method] {
			seen[route.method] = true
			methods = append(methods, route.method)
		}
	}
	return strings.Join(methods, ", ")
}

func writeError(writer http.ResponseWriter, status int) {
	code := "internal_server_error"
	switch status {
	case http.StatusBadRequest:
		code = "bad_request"
	case http.StatusUnauthorized:
		code = "unauthorized"
	case http.StatusForbidden:
		code = "forbidden"
	case http.StatusNotFound:
		code = "not_found"
	case http.StatusMethodNotAllowed:
		code = "method_not_allowed"
	case http.StatusTooManyRequests:
		code = "rate_limit_exceeded"
	case http.StatusServiceUnavailable:
		code = "service_unavailable"
	}
	writeJSONError(writer, status, code)
}

func writeAppError(writer http.ResponseWriter, err error) {
	status, code := http.StatusInternalServerError, "internal_server_error"
	switch {
	case errors.Is(err, ErrUnauthenticated):
		status, code = http.StatusUnauthorized, "unauthorized"
	case errors.Is(err, ErrForbidden):
		status, code = http.StatusForbidden, "forbidden"
	case errors.Is(err, ErrNotFound):
		status, code = http.StatusNotFound, "not_found"
	case errors.Is(err, ErrMethodNotAllowed):
		status, code = http.StatusMethodNotAllowed, "method_not_allowed"
	case errors.Is(err, ErrRateLimitExceeded):
		status, code = http.StatusTooManyRequests, "rate_limit_exceeded"
	case errors.Is(err, ErrQueueFull):
		status, code = http.StatusServiceUnavailable, "service_unavailable"
	}
	writeJSONError(writer, status, code)
}

func writeJSONError(writer http.ResponseWriter, status int, code string) {
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(struct {
		Error string `json:"error"`
	}{Error: code})
}
