package goxis

import (
	"encoding/json"
	"net/http"
	"sync"
)

// Context carries request, route parameters, and response helpers for handlers.
type Context struct {
	Writer        http.ResponseWriter
	Request       *http.Request
	params        map[string]string
	values        map[string]any
	mu            sync.RWMutex
	written       bool
	authenticated bool
}

func newContext(writer http.ResponseWriter, request *http.Request, params map[string]string) *Context {
	return &Context{Writer: writer, Request: request, params: params, values: make(map[string]any)}
}

// Param returns a named path parameter.
func (ctx *Context) Param(name string) string { return ctx.params[name] }

// Query returns the first query value for name.
func (ctx *Context) Query(name string) string { return ctx.Request.URL.Query().Get(name) }

// Set stores a value for middleware and handlers during the request.
func (ctx *Context) Set(key string, value any) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.values[key] = value
}

// Get retrieves a value stored by Set.
func (ctx *Context) Get(key string) (any, bool) {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	value, ok := ctx.values[key]
	return value, ok
}

// JSON writes a JSON response with the given status code.
func (ctx *Context) JSON(status int, value any) error {
	ctx.Writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	ctx.WriteHeader(status)
	return json.NewEncoder(ctx.Writer).Encode(value)
}

// Text writes a plain text response with the given status code.
func (ctx *Context) Text(status int, value string) error {
	ctx.Writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	ctx.WriteHeader(status)
	_, err := ctx.Writer.Write([]byte(value))
	return err
}

// WriteHeader sends the response status. Only the first call takes effect.
func (ctx *Context) WriteHeader(status int) {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	if ctx.written {
		return
	}
	ctx.written = true
	ctx.Writer.WriteHeader(status)
}

// Written reports whether the response has started.
func (ctx *Context) Written() bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return ctx.written
}

// MarkAuthenticated records that authentication middleware validated this
// request before the protected handler runs.
func (ctx *Context) MarkAuthenticated() {
	ctx.mu.Lock()
	defer ctx.mu.Unlock()
	ctx.authenticated = true
}

// Authenticated reports whether middleware authenticated this request.
func (ctx *Context) Authenticated() bool {
	ctx.mu.RLock()
	defer ctx.mu.RUnlock()
	return ctx.authenticated
}
