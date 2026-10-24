package log

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"
)

var exitProcess = os.Exit

// Logger writes formatted records to the configured io.Writer.
type Logger struct {
	mu  sync.Mutex
	cfg Config
}

// New creates a logger with the defaults and applies the supplied options.
func New(options ...Option) *Logger {
	cfg := NewConfig()
	for _, option := range options {
		if option != nil {
			option(&cfg)
		}
	}
	if cfg.Writer == nil {
		cfg.Writer = os.Stdout
	}
	if !cfg.Format.IsValid() {
		cfg.Format = FormatText
	}
	return &Logger{cfg: cfg}
}

// Log writes a record at level. Records below the configured threshold are ignored.
func (l *Logger) Log(level Level, message string) { l.log(level, message, nil) }

func (l *Logger) log(level Level, message string, fields map[string]any) {
	if l == nil || !level.IsValid() || !level.Enabled(l.cfg.Level) {
		return
	}
	record := Record{Time: time.Now(), Level: level.String(), Message: message, Fields: fields}
	var output string
	if l.cfg.Format == FormatJSON {
		output = formatJSON(record)
	} else {
		output = formatText(record, l.cfg)
	}
	l.mu.Lock()
	_, err := fmt.Fprint(l.cfg.Writer, output)
	l.mu.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "log: write failed: %v\n", err)
	}
	if level == LevelFatal {
		exitProcess(1)
	}
	if level == LevelPanic {
		panic(message)
	}
}

func (l *Logger) Trace(message string)   { l.log(LevelTrace, message, nil) }
func (l *Logger) Debug(message string)   { l.log(LevelDebug, message, nil) }
func (l *Logger) Info(message string)    { l.log(LevelInfo, message, nil) }
func (l *Logger) Success(message string) { l.log(LevelSuccess, message, nil) }
func (l *Logger) Warn(message string)    { l.log(LevelWarn, message, nil) }
func (l *Logger) Error(message string)   { l.log(LevelError, message, nil) }
func (l *Logger) Fatal(message string)   { l.log(LevelFatal, message, nil) }
func (l *Logger) Panic(message string)   { l.log(LevelPanic, message, nil) }

func (l *Logger) Tracef(format string, args ...any) { l.Trace(fmt.Sprintf(format, args...)) }
func (l *Logger) Debugf(format string, args ...any) { l.Debug(fmt.Sprintf(format, args...)) }
func (l *Logger) Infof(format string, args ...any)  { l.Info(fmt.Sprintf(format, args...)) }
func (l *Logger) Warnf(format string, args ...any)  { l.Warn(fmt.Sprintf(format, args...)) }
func (l *Logger) Errorf(format string, args ...any) { l.Error(fmt.Sprintf(format, args...)) }

func (l *Logger) InfoWithFields(message string, fields map[string]any) {
	l.log(LevelInfo, message, fields)
}
func (l *Logger) DebugWithFields(message string, fields map[string]any) {
	l.log(LevelDebug, message, fields)
}
func (l *Logger) WarnWithFields(message string, fields map[string]any) {
	l.log(LevelWarn, message, fields)
}
func (l *Logger) ErrorWithFields(message string, fields map[string]any) {
	l.log(LevelError, message, fields)
}
func (l *Logger) SuccessWithFields(message string, fields map[string]any) {
	l.log(LevelSuccess, message, fields)
}

// HTTPRequest writes an access-log line in the Goxis request format. The
// status controls the severity/color; JSON loggers keep their configured JSON
// format and include the same values as structured fields.
func (l *Logger) HTTPRequest(method, requestURI string, status int, clientIP string, duration time.Duration) {
	level := requestLevel(status)
	if l == nil {
		return
	}
	fields := map[string]any{
		"method": method, "request_uri": requestURI, "status": status,
		"duration": duration.String(), "client_ip": clientIP,
	}
	if l.cfg.Format == FormatJSON {
		output := formatJSON(Record{Time: time.Now(), Level: level.String(), Message: "HTTP request", Fields: fields})
		l.write(output)
	} else {
		statusText := fmt.Sprintf("%3d", status)
		if l.cfg.EnableColor {
			statusText = level.Color() + statusText + colorReset
		}
		line := fmt.Sprintf("[GOXIS] %s | %s | %8s | %15s | %-8s %q\n",
			time.Now().Format("2006/01/02 - 15:04:05"), statusText,
			duration.String(), clientIP, method, requestURI,
		)
		l.write(line)
	}
}

func (l *Logger) write(output string) {
	l.mu.Lock()
	_, err := fmt.Fprint(l.cfg.Writer, output)
	l.mu.Unlock()
	if err != nil {
		fmt.Fprintf(os.Stderr, "log: write failed: %v\n", err)
	}
}

func requestLevel(status int) Level {
	switch {
	case status >= http.StatusInternalServerError:
		return LevelError
	case status >= http.StatusBadRequest:
		return LevelWarn
	case status >= http.StatusMultipleChoices:
		return LevelInfo
	default:
		return LevelSuccess
	}
}

var (
	defaultMu     sync.RWMutex
	defaultLogger = New()
)

// SetDefault replaces the logger used by package-level functions.
func SetDefault(l *Logger) {
	if l == nil {
		return
	}
	defaultMu.Lock()
	defaultLogger = l
	defaultMu.Unlock()
}

// GetDefault returns the logger used by package-level functions.
func GetDefault() *Logger { defaultMu.RLock(); defer defaultMu.RUnlock(); return defaultLogger }

func Trace(message string)   { GetDefault().Trace(message) }
func Debug(message string)   { GetDefault().Debug(message) }
func Info(message string)    { GetDefault().Info(message) }
func Success(message string) { GetDefault().Success(message) }
func Warn(message string)    { GetDefault().Warn(message) }
func Error(message string)   { GetDefault().Error(message) }
func Fatal(message string)   { GetDefault().Fatal(message) }
func Panic(message string)   { GetDefault().Panic(message) }
func InfoWithFields(message string, fields map[string]any) {
	GetDefault().InfoWithFields(message, fields)
}
func DebugWithFields(message string, fields map[string]any) {
	GetDefault().DebugWithFields(message, fields)
}
func WarnWithFields(message string, fields map[string]any) {
	GetDefault().WarnWithFields(message, fields)
}
func ErrorWithFields(message string, fields map[string]any) {
	GetDefault().ErrorWithFields(message, fields)
}
func SuccessWithFields(message string, fields map[string]any) {
	GetDefault().SuccessWithFields(message, fields)
}

// HTTPRequest logs an HTTP request using the default logger.
func HTTPRequest(method, requestURI string, status int, clientIP string, duration time.Duration) {
	GetDefault().HTTPRequest(method, requestURI, status, clientIP, duration)
}
