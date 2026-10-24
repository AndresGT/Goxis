package log

import "strings"

// Level is the severity of a log record. Higher levels are more severe.
type Level uint8

const (
	LevelTrace Level = iota
	LevelDebug
	LevelInfo
	LevelSuccess
	LevelWarn
	LevelError
	LevelFatal
	LevelPanic
)

// GoKit-style aliases keep the API familiar to users of the sibling module.
const (
	TraceLevel   = LevelTrace
	DebugLevel   = LevelDebug
	InfoLevel    = LevelInfo
	SuccessLevel = LevelSuccess
	WarnLevel    = LevelWarn
	ErrorLevel   = LevelError
	FatalLevel   = LevelFatal
	PanicLevel   = LevelPanic
)

var levelNames = [...]string{"TRACE", "DEBUG", "INFO", "SUCCESS", "WARN", "ERROR", "FATAL", "PANIC"}

func (l Level) String() string {
	if !l.IsValid() {
		return "UNKNOWN"
	}
	return levelNames[l]
}

func (l Level) IsValid() bool          { return l <= LevelPanic }
func (l Level) Enabled(min Level) bool { return l >= min }
func (l Level) Prefix() string         { return "[" + l.String() + "]" }

func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return LevelDebug, nil
	case "info":
		return LevelInfo, nil
	case "success":
		return LevelSuccess, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "error":
		return LevelError, nil
	case "fatal":
		return LevelFatal, nil
	case "panic":
		return LevelPanic, nil
	default:
		return LevelInfo, ErrInvalidLevel
	}
}

func (l Level) Color() string {
	switch l {
	case LevelTrace:
		return "\033[90m"
	case LevelDebug:
		return "\033[36m"
	case LevelInfo:
		return "\033[34m"
	case LevelSuccess:
		return "\033[32m"
	case LevelWarn:
		return "\033[33m"
	case LevelError:
		return "\033[31m"
	case LevelFatal:
		return "\033[1;31m"
	case LevelPanic:
		return "\033[1;35m"
	default:
		return ""
	}
}

const colorReset = "\033[0m"
