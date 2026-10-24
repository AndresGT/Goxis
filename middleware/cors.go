package middleware

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var ErrInvalidCORSConfig = errors.New("goxis: invalid CORS configuration")
var ErrInvalidOriginGuardConfig = errors.New("goxis: invalid origin guard configuration")

// Middleware wraps an HTTP handler with cross-origin response handling.
type Middleware func(http.Handler) http.Handler

type httpMiddlewareRegistrar interface {
	RegisterHTTPMiddleware(func(http.Handler) http.Handler, error)
}

// CORSConfig controls which browser origins may read responses from the app.
// Empty methods and headers use conservative defaults. Origins default to none.
type CORSConfig struct {
	AllowedOrigins   []string
	AllowedMethods   []string
	AllowedHeaders   []string
	ExposedHeaders   []string
	AllowCredentials bool
	MaxAge           int // Preflight cache duration in seconds; maximum is 86400.
}

// Validate checks the configuration before the application starts.
func (config CORSConfig) Validate() error {
	_, err := compileCORSConfig(config)
	return err
}

type corsPolicy struct {
	origins          map[string]struct{}
	wildcard         bool
	methods          []string
	methodSet        map[string]struct{}
	headers          []string
	headerSet        map[string]struct{}
	exposedHeaders   []string
	allowCredentials bool
	maxAge           int
}

func compileCORSConfig(config CORSConfig) (*corsPolicy, error) {
	if config.MaxAge < 0 || config.MaxAge > 86400 {
		return nil, fmt.Errorf("%w: MaxAge must be between 0 and 86400 seconds", ErrInvalidCORSConfig)
	}
	policy := &corsPolicy{
		origins:          make(map[string]struct{}, len(config.AllowedOrigins)),
		methodSet:        make(map[string]struct{}),
		headerSet:        make(map[string]struct{}),
		allowCredentials: config.AllowCredentials,
		maxAge:           config.MaxAge,
	}
	for _, origin := range config.AllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "*" {
			policy.wildcard = true
			continue
		}
		normalized, err := normalizeOrigin(origin)
		if err != nil {
			return nil, fmt.Errorf("%w: %q is not an http(s) origin", ErrInvalidCORSConfig, origin)
		}
		policy.origins[normalized] = struct{}{}
	}
	if policy.wildcard && policy.allowCredentials {
		return nil, fmt.Errorf("%w: wildcard origins cannot be combined with credentials", ErrInvalidCORSConfig)
	}

	methods := config.AllowedMethods
	if len(methods) == 0 {
		methods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}
	}
	for _, method := range methods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if !validToken(method) || method == "*" {
			return nil, fmt.Errorf("%w: invalid allowed method %q", ErrInvalidCORSConfig, method)
		}
		if _, exists := policy.methodSet[method]; !exists {
			policy.methodSet[method] = struct{}{}
			policy.methods = append(policy.methods, method)
		}
	}

	headers := config.AllowedHeaders
	if len(headers) == 0 {
		headers = []string{"Authorization", "Content-Type"}
	}
	for _, header := range headers {
		header = strings.TrimSpace(header)
		if !validToken(header) || header == "*" {
			return nil, fmt.Errorf("%w: invalid allowed header %q", ErrInvalidCORSConfig, header)
		}
		key := strings.ToLower(header)
		if _, exists := policy.headerSet[key]; !exists {
			policy.headerSet[key] = struct{}{}
			policy.headers = append(policy.headers, http.CanonicalHeaderKey(header))
		}
	}

	for _, header := range config.ExposedHeaders {
		header = strings.TrimSpace(header)
		if !validToken(header) || header == "*" {
			return nil, fmt.Errorf("%w: invalid exposed header %q", ErrInvalidCORSConfig, header)
		}
		policy.exposedHeaders = append(policy.exposedHeaders, http.CanonicalHeaderKey(header))
	}
	return policy, nil
}

func normalizeOrigin(origin string) (string, error) {
	if origin == "null" {
		return origin, nil
	}
	// localhost:port is accepted as a development shorthand for an HTTP origin.
	if strings.HasPrefix(strings.ToLower(origin), "localhost:") {
		origin = "http://" + origin
	}
	u, err := url.Parse(origin)
	if err != nil || u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || strings.HasSuffix(u.Host, ":") || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("invalid origin")
	}
	hostname := strings.ToLower(u.Hostname())
	if hostname == "" {
		return "", errors.New("invalid origin host")
	}
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
	}
	host := hostname
	if strings.Contains(hostname, ":") {
		host = "[" + hostname + "]"
	}
	if port != "" {
		host = net.JoinHostPort(hostname, port)
	}
	return strings.ToLower(u.Scheme) + "://" + host, nil
}

func validToken(value string) bool {
	if value == "" {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		if strings.ContainsRune("!#$%&'*+-.^_`|~", rune(c)) {
			continue
		}
		return false
	}
	return true
}

// CORS returns HTTP middleware for the supplied policy. When applied directly
// to a Goxis App, it registers itself on that app and returns the app, allowing
// initialization code to call CORS(config)(app) without wrapping main. For any
// other handler it returns the usual wrapped handler. Invalid configurations
// are reported by App.Run and fail closed with 500 responses otherwise.
func CORS(config CORSConfig) Middleware {
	policy, err := compileCORSConfig(config)
	wrap := func(next http.Handler) http.Handler {
		if err != nil {
			return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			})
		}
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if policy.handle(writer, request) {
				return
			}
			next.ServeHTTP(writer, request)
		})
	}
	return func(next http.Handler) http.Handler {
		if registrar, ok := next.(httpMiddlewareRegistrar); ok {
			registrar.RegisterHTTPMiddleware(wrap, err)
			return next
		}
		return wrap(next)
	}
}

// OriginGuard rejects requests that do not carry exactly one allowed Origin.
// This is an additional browser-origin filter, not client authentication.
// Use full http(s) origins; localhost:port is accepted as an HTTP shorthand.
func OriginGuard(allowedOrigins ...string) Middleware {
	origins := make(map[string]struct{}, len(allowedOrigins))
	var configErr error
	for _, origin := range allowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin == "*" {
			configErr = fmt.Errorf("%w: wildcard is not allowed", ErrInvalidOriginGuardConfig)
			break
		}
		normalized, err := normalizeOrigin(origin)
		if err != nil {
			configErr = fmt.Errorf("%w: %q is not an http(s) origin", ErrInvalidOriginGuardConfig, origin)
			break
		}
		origins[normalized] = struct{}{}
	}
	if len(allowedOrigins) == 0 {
		configErr = fmt.Errorf("%w: at least one origin is required", ErrInvalidOriginGuardConfig)
	}

	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if configErr != nil {
				http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			requestOrigins := request.Header.Values("Origin")
			if len(requestOrigins) != 1 {
				http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			normalized, err := normalizeOrigin(strings.TrimSpace(requestOrigins[0]))
			if err != nil {
				http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			if _, allowed := origins[normalized]; !allowed {
				http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
				return
			}
			next.ServeHTTP(writer, request)
		})
	}
	return func(next http.Handler) http.Handler {
		if registrar, ok := next.(httpMiddlewareRegistrar); ok {
			registrar.RegisterHTTPMiddleware(wrap, configErr)
			return next
		}
		return wrap(next)
	}
}

func (policy *corsPolicy) handle(writer http.ResponseWriter, request *http.Request) bool {
	origin := request.Header.Get("Origin")
	if origin == "" {
		return false
	}
	addVary(writer.Header(), "Origin")

	normalized, err := normalizeOrigin(origin)
	_, originAllowed := policy.origins[normalized]
	if policy.wildcard {
		originAllowed = true
	}
	preflightMethod := request.Header.Get("Access-Control-Request-Method")
	requestedHeadersValue := request.Header.Get("Access-Control-Request-Headers")
	isPreflight := request.Method == http.MethodOptions && (preflightMethod != "" || requestedHeadersValue != "")
	if isPreflight {
		addVary(writer.Header(), "Access-Control-Request-Method")
		addVary(writer.Header(), "Access-Control-Request-Headers")
		if strings.TrimSpace(preflightMethod) == "" {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return true
		}
		if err != nil || !originAllowed {
			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return true
		}
		method := strings.ToUpper(strings.TrimSpace(preflightMethod))
		if _, ok := policy.methodSet[method]; !ok {
			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return true
		}
		requestedHeaders, ok := policy.allowedRequestedHeaders(requestedHeadersValue)
		if !ok {
			http.Error(writer, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return true
		}
		policy.setOriginHeaders(writer.Header(), origin)
		writer.Header().Set("Access-Control-Allow-Methods", strings.Join(policy.methods, ", "))
		if len(requestedHeaders) > 0 {
			writer.Header().Set("Access-Control-Allow-Headers", strings.Join(requestedHeaders, ", "))
		}
		if policy.maxAge > 0 {
			writer.Header().Set("Access-Control-Max-Age", strconv.Itoa(policy.maxAge))
		}
		writer.WriteHeader(http.StatusNoContent)
		return true
	}

	if err != nil || !originAllowed {
		return false
	}
	if _, methodAllowed := policy.methodSet[request.Method]; !methodAllowed {
		return false
	}
	policy.setOriginHeaders(writer.Header(), origin)
	if len(policy.exposedHeaders) > 0 {
		writer.Header().Set("Access-Control-Expose-Headers", strings.Join(policy.exposedHeaders, ", "))
	}
	return false
}

func (policy *corsPolicy) setOriginHeaders(headers http.Header, origin string) {
	if policy.wildcard {
		headers.Set("Access-Control-Allow-Origin", "*")
	} else {
		headers.Set("Access-Control-Allow-Origin", origin)
	}
	if policy.allowCredentials {
		headers.Set("Access-Control-Allow-Credentials", "true")
	}
}

func (policy *corsPolicy) allowedRequestedHeaders(value string) ([]string, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, true
	}
	requested := strings.Split(value, ",")
	allowed := make([]string, 0, len(requested))
	seen := make(map[string]bool, len(requested))
	for _, header := range requested {
		header = strings.TrimSpace(header)
		if !validToken(header) {
			return nil, false
		}
		key := strings.ToLower(header)
		if _, ok := policy.headerSet[key]; !ok {
			return nil, false
		}
		if !seen[key] {
			seen[key] = true
			allowed = append(allowed, http.CanonicalHeaderKey(header))
		}
	}
	return allowed, true
}

func addVary(headers http.Header, value string) {
	for _, existing := range headers.Values("Vary") {
		for _, item := range strings.Split(existing, ",") {
			if strings.TrimSpace(item) == "*" {
				return
			}
			if strings.EqualFold(strings.TrimSpace(item), value) {
				return
			}
		}
	}
	headers.Add("Vary", value)
}
