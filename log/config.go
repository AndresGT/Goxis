package log

import (
	"io"
	"os"
)

// Config controls how log records are formatted and where they are written.
// The writer defaults to standard output and can be replaced by the caller.
type Config struct {
	Writer      io.Writer
	Level       Level
	Format      Format
	EnableColor bool
	TimeFormat  string
}

func defaultConfig() Config {
	return Config{
		Writer:      os.Stdout,
		Level:       LevelInfo,
		Format:      FormatText,
		EnableColor: true,
		TimeFormat:  "2006-01-02 15:04:05",
	}
}

// NewConfig returns the default logger configuration.
func NewConfig() Config { return defaultConfig() }
