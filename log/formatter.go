package log

import (
	"strings"
)

type Format uint

const (
	FormatText Format = iota
	FormatJSON
)

func (f Format) String() string {
	switch f {
	case FormatText:
		return "text"
	case FormatJSON:
		return "json"
	default:
		return "unknown"
	}
}

func (f Format) IsValid() bool {
	return f == FormatText || f == FormatJSON
}

func ParseFormat(s string) (Format, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "text":
		return FormatText, nil
	case "json":
		return FormatJSON, nil
	default:
		return FormatText, ErrInvalidFormat
	}
}
