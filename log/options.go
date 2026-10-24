package log

import "io"

// Option configures a Logger when passed to New.
type Option func(*Config)

func WithLevel(level Level) Option {
	return func(c *Config) {
		if level.IsValid() {
			c.Level = level
		}
	}
}
func WithWriter(w io.Writer) Option {
	return func(c *Config) {
		if w != nil {
			c.Writer = w
		}
	}
}
func WithColor(enabled bool) Option { return func(c *Config) { c.EnableColor = enabled } }
func WithFormat(format Format) Option {
	return func(c *Config) {
		if format.IsValid() {
			c.Format = format
		}
	}
}
func WithTimeFormat(layout string) Option {
	return func(c *Config) {
		if layout != "" {
			c.TimeFormat = layout
		}
	}
}
