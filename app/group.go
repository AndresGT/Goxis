package goxis

import (
	"fmt"
	"strings"

	goxislog "github.com/AndresGT/Goxis/log"
)

// Route describes one endpoint registered by a module.
type Route struct {
	Method        string
	Path          string
	Handler       Handler
	Protected     bool
	RateLimit     int      // Requests per minute from one client IP; zero disables it.
	MaxConcurrent int      // Maximum handlers running for this route; zero is unlimited.
	QueueLimit    int      // Additional waiting requests; zero disables queuing.
	Roles         []string // One of these roles is sufficient for this route.
	Permission    string   // Resource name; the HTTP method supplies the action.
	Permissions   []string
	Middleware    []Middleware
}

type routeEntry struct {
	method        string
	path          string
	group         string
	handler       Handler
	middleware    []Middleware
	policy        Policy
	protected     bool
	limiter       *routeLimiter
	rateLimit     int
	queue         *requestQueue
	maxConcurrent int
	queueLimit    int
}

// GroupOption configures a route group.
type GroupOption func(*Group)

// Group collects routes under a common path, middleware chain, and access policy.
type Group struct {
	app        *App
	prefix     string
	middleware []Middleware
	policy     Policy
}

// WithMiddleware adds middleware to a group and all its child routes.
func WithMiddleware(middleware ...Middleware) GroupOption {
	return func(group *Group) {
		group.middleware = append(group.middleware, nonNilMiddleware(middleware)...)
	}
}

// WithRoles requires every listed role on routes registered in the group.
func WithRoles(roles ...string) GroupOption {
	return func(group *Group) { group.policy.Roles = append(group.policy.Roles, roles...) }
}

// WithPermissions requires every listed permission on routes registered in the group.
func WithPermissions(permissions ...string) GroupOption {
	return func(group *Group) {
		group.policy.Permissions = append(group.policy.Permissions, permissions...)
	}
}

// Group creates a child group. Middleware and policies are inherited; child
// options can add requirements but cannot remove inherited requirements.
func (group *Group) Group(prefix string, options ...GroupOption) *Group {
	child := &Group{
		app:        group.app,
		prefix:     joinPath(group.prefix, prefix),
		middleware: append([]Middleware(nil), group.middleware...),
		policy: Policy{
			Roles:       append([]string(nil), group.policy.Roles...),
			AnyRole:     append([]string(nil), group.policy.AnyRole...),
			Permissions: append([]string(nil), group.policy.Permissions...),
		},
	}
	applyGroupOptions(child, options)
	return child
}

// RegisterRoutes adds routes relative to this group's prefix.
func (group *Group) RegisterRoutes(routes []Route) error {
	entries := make([]routeEntry, 0, len(routes))
	batch := make(map[string]bool, len(routes))
	for _, route := range routes {
		method := strings.ToUpper(strings.TrimSpace(route.Method))
		path := joinPath(group.prefix, route.Path)
		if method == "" || route.Handler == nil || !validPattern(path) {
			return fmt.Errorf("%w: method, handler, or path is invalid (%q %q)", ErrInvalidRoute, route.Method, path)
		}
		if route.RateLimit < 0 || route.MaxConcurrent < 0 || route.QueueLimit < 0 || (route.QueueLimit > 0 && route.MaxConcurrent == 0) || route.MaxConcurrent > maxRouteQueueCapacity || route.QueueLimit > maxRouteQueueCapacity-route.MaxConcurrent {
			return fmt.Errorf("%w: invalid rate limit or queue configuration for %s %s", ErrInvalidRoute, method, path)
		}
		permissions := append(append([]string(nil), group.policy.Permissions...), route.Permissions...)
		resourcePermission := route.Permission
		mapAction := resourcePermission != "" || (len(permissions) == 0 && (len(route.Roles) > 0 || len(group.policy.Roles) > 0 || len(group.policy.AnyRole) > 0))
		if mapAction {
			mapped, err := permissionForMethod(method, resourcePermission)
			if err != nil {
				return fmt.Errorf("%w: %s %s has no permission mapping", ErrInvalidRoute, method, path)
			}
			permissions = append(permissions, mapped)
		}
		key := method + " " + path
		if batch[key] {
			return fmt.Errorf("%w: %s", ErrDuplicateRoute, key)
		}
		batch[key] = true
		entries = append(entries, routeEntry{
			method:     method,
			path:       path,
			group:      group.prefix,
			handler:    route.Handler,
			middleware: append(append([]Middleware(nil), group.middleware...), nonNilMiddleware(route.Middleware)...),
			policy: Policy{
				Roles:       append([]string(nil), group.policy.Roles...),
				AnyRole:     append(append([]string(nil), group.policy.AnyRole...), route.Roles...),
				Permissions: permissions,
			},
			protected:     route.Protected || len(group.policy.Roles) > 0 || len(group.policy.AnyRole) > 0 || len(permissions) > 0,
			limiter:       newRouteLimiter(route.RateLimit),
			rateLimit:     route.RateLimit,
			queue:         newRequestQueue(route.MaxConcurrent, route.QueueLimit),
			maxConcurrent: route.MaxConcurrent,
			queueLimit:    route.QueueLimit,
		})
	}

	group.app.mu.Lock()
	for _, entry := range entries {
		for _, current := range group.app.routes {
			if routePatternsConflict(current, entry) {
				group.app.mu.Unlock()
				return fmt.Errorf("%w: ambiguous route %s %s conflicts with %s %s", ErrDuplicateRoute, entry.method, entry.path, current.method, current.path)
			}
		}
	}
	for i, entry := range entries {
		for _, other := range entries[i+1:] {
			if routePatternsConflict(entry, other) {
				group.app.mu.Unlock()
				return fmt.Errorf("%w: ambiguous routes %s %s and %s %s", ErrDuplicateRoute, entry.method, entry.path, other.method, other.path)
			}
		}
	}
	group.app.routes = append(group.app.routes, entries...)
	group.app.mu.Unlock()
	for _, entry := range entries {
		logRouteRegistered(entry)
	}
	return nil
}

func routePatternsConflict(a, b routeEntry) bool {
	methodsConflict := a.method == b.method || (a.method == GET && b.method == HEAD) || (a.method == HEAD && b.method == GET)
	if !methodsConflict {
		return false
	}
	pa, pb := splitPath(a.path), splitPath(b.path)
	if len(pa) != len(pb) {
		return false
	}
	for i := range pa {
		as, bs := routeParamName(pa[i]) == "", routeParamName(pb[i]) == ""
		if as && bs && pa[i] != pb[i] {
			return false
		}
		if as != bs {
			return false
		}
	}
	return true
}

func routeParamName(segment string) string {
	if strings.HasPrefix(segment, ":") {
		return strings.TrimPrefix(segment, ":")
	}
	if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
		return strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
	}
	return ""
}

func logRouteRegistered(route routeEntry) {
	access := "pública"
	icon := "🔓"
	if route.protected || len(route.policy.Roles) > 0 || len(route.policy.AnyRole) > 0 || len(route.policy.Permissions) > 0 {
		icon = "🔒"
		access = "protegida (autenticación requerida)"
		if len(route.policy.Roles) > 0 || len(route.policy.AnyRole) > 0 || len(route.policy.Permissions) > 0 {
			access = fmt.Sprintf("protegida roles=%v any-role=%v permisos=%v", route.policy.Roles, route.policy.AnyRole, route.policy.Permissions)
		}
	}
	if route.rateLimit > 0 {
		access += fmt.Sprintf(" rate-limit=%d/min", route.rateLimit)
	}
	if route.maxConcurrent > 0 {
		access += fmt.Sprintf(" concurrency=%d queue=%d", route.maxConcurrent, route.queueLimit)
	}
	goxislog.Info(fmt.Sprintf("%s [%s] %s | grupo: %s | acceso: %s", icon, route.method, route.path, route.group, access))
}

func permissionForMethod(method, resource string) (string, error) {
	resource = strings.TrimSpace(resource)
	if strings.Contains(resource, ":") {
		return resource, nil
	}
	var action string
	switch method {
	case GET, HEAD:
		action = "read"
	case POST:
		action = "create"
	case PUT, PATCH:
		action = "edit"
	case DELETE:
		action = "delete"
	default:
		return "", ErrInvalidRoute
	}
	if resource == "" {
		return action, nil
	}
	return resource + ":" + action, nil
}

func applyGroupOptions(group *Group, options []GroupOption) {
	for _, option := range options {
		if option != nil {
			option(group)
		}
	}
}

func nonNilMiddleware(middleware []Middleware) []Middleware {
	result := make([]Middleware, 0, len(middleware))
	for _, item := range middleware {
		if item != nil {
			result = append(result, item)
		}
	}
	return result
}

func cleanPath(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	parts := strings.FieldsFunc(path, func(r rune) bool { return r == '/' })
	return "/" + strings.Join(parts, "/")
}

func joinPath(prefix, path string) string {
	if cleanPath(prefix) == "/" {
		return cleanPath(path)
	}
	if cleanPath(path) == "/" {
		return cleanPath(prefix)
	}
	return cleanPath(prefix + "/" + path)
}

func validPattern(path string) bool {
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		if strings.HasPrefix(segment, ":") && len(segment) == 1 {
			return false
		}
		if strings.Contains(segment, "{") || strings.Contains(segment, "}") {
			if !(strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && len(segment) > 2) {
				return false
			}
		}
	}
	return true
}

func matchPath(pattern, path string) (map[string]string, bool) {
	patternParts := splitPath(pattern)
	pathParts := splitPath(path)
	if len(patternParts) != len(pathParts) {
		return nil, false
	}
	params := make(map[string]string)
	for i, part := range patternParts {
		name := ""
		if strings.HasPrefix(part, ":") {
			name = strings.TrimPrefix(part, ":")
		} else if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			name = strings.TrimSuffix(strings.TrimPrefix(part, "{"), "}")
		}
		if name != "" {
			params[name] = pathParts[i]
		} else if part != pathParts[i] {
			return nil, false
		}
	}
	return params, true
}

func splitPath(path string) []string {
	if cleanPath(path) == "/" {
		return nil
	}
	return strings.Split(strings.Trim(cleanPath(path), "/"), "/")
}
