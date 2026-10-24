package goxis

import (
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
	started := time.Now()
	recorder := &responseRecorder{ResponseWriter: writer}
	defer func() {
		if recovered := recover(); recovered != nil {
			if recorder.status == 0 {
				http.Error(recorder, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
			logRequest(request, recorder.status, time.Since(started))
			return
		}
		status := recorder.status
		if status == 0 {
			status = http.StatusOK
		}
		logRequest(request, status, time.Since(started))
	}()

	app.mu.RLock()
	middlewares := append([]func(http.Handler) http.Handler(nil), app.httpMiddleware...)
	app.mu.RUnlock()

	var handler http.Handler = http.HandlerFunc(app.serveRoutes)
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
	handler := entry.handler
	if entry.limiter != nil && !entry.limiter.allow(remoteIP(request.RemoteAddr), time.Now()) {
		writer.Header().Set("Retry-After", "60")
		writeError(writer, http.StatusTooManyRequests)
		return
	}
	if entry.queue != nil {
		next := handler
		handler = func(ctx *Context) error {
			release, admitted := entry.queue.acquire(ctx.Request.Context())
			if !admitted {
				if ctx.Request.Context().Err() == nil {
					ctx.Writer.Header().Set("Retry-After", "1")
					writeError(ctx.Writer, http.StatusServiceUnavailable)
				}
				return nil
			}
			defer release()
			return next(ctx)
		}
	}
	if entry.protected || len(entry.policy.Roles) > 0 || len(entry.policy.AnyRole) > 0 || len(entry.policy.Permissions) > 0 {
		next := handler
		handler = func(ctx *Context) error {
			hasPolicy := len(entry.policy.Roles) > 0 || len(entry.policy.AnyRole) > 0 || len(entry.policy.Permissions) > 0
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

	middlewares := append(globalMiddleware, entry.middleware...)
	for i := len(middlewares) - 1; i >= 0; i-- {
		handler = middlewares[i](handler)
	}
	if err := handler(ctx); err != nil && !ctx.Written() {
		status := http.StatusInternalServerError
		switch {
		case errors.Is(err, ErrUnauthenticated):
			status = http.StatusUnauthorized
		case errors.Is(err, ErrForbidden):
			status = http.StatusForbidden
		}
		writeError(writer, status)
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
	http.Error(writer, http.StatusText(status), status)
}
