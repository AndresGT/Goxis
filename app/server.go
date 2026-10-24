package goxis

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	goxislog "github.com/AndresGT/Goxis/log"
)

// HTTPServerConfig controls HTTP connection and header limits. Use
// DefaultHTTPServerConfig and override only the values your deployment needs.
type HTTPServerConfig struct {
	ReadHeaderTimeout time.Duration
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	IdleTimeout       time.Duration
	MaxHeaderBytes    int
}

// DefaultHTTPServerConfig returns bounded defaults for a JSON API server.
func DefaultHTTPServerConfig() HTTPServerConfig {
	return HTTPServerConfig{
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    1 << 20,
	}
}

func (config HTTPServerConfig) validate() error {
	if config.ReadHeaderTimeout < 0 || config.ReadTimeout < 0 || config.WriteTimeout < 0 || config.IdleTimeout < 0 || config.MaxHeaderBytes < 0 {
		return errors.New("goxis: HTTP server limits cannot be negative")
	}
	return nil
}

// WithHTTPServerConfig sets the listener limits applied by Run, RunHandler and
// NewHTTPServer. Zero disables a timeout/header limit when explicitly set.
func WithHTTPServerConfig(config HTTPServerConfig) Option {
	return func(app *App) {
		if err := config.validate(); err != nil {
			if app.startupErr == nil {
				app.startupErr = err
			} else {
				app.startupErr = errors.Join(app.startupErr, err)
			}
			return
		}
		app.serverConfig = config
	}
}

// NewHTTPServer creates a configured server that the application can start in
// its own goroutine and stop with Shutdown for graceful termination. Zero
// timeout values disable that timeout; MaxHeaderBytes zero uses net/http's default.
func (app *App) NewHTTPServer(addr string, handler http.Handler) (*http.Server, error) {
	if handler == nil {
		handler = app
	}
	app.mu.RLock()
	defer app.mu.RUnlock()
	if app.startupErr != nil {
		return nil, fmt.Errorf("goxis: application configuration failed: %w", app.startupErr)
	}
	cfg := app.serverConfig
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		IdleTimeout:       cfg.IdleTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}, nil
}

// Run starts the application's HTTP server at addr.
func (app *App) Run(addr string) error {
	return app.RunHandler(addr, app)
}

// RunHandler starts the application server with an outer HTTP handler, such
// as middleware.CORS(config)(app).
func (app *App) RunHandler(addr string, handler http.Handler) error {
	if handler == nil {
		handler = app
	}
	server, err := app.NewHTTPServer(addr, handler)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	app.mu.RLock()
	routeCount := len(app.routes)
	app.mu.RUnlock()
	goxislog.Info(fmt.Sprintf("Goxis escuchando en %s | rutas registradas: %d", listener.Addr(), routeCount))
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
