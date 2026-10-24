package log

import (
	"fmt"
	"strings"
)

func formatText(record Record, cfg Config) string {
	var b strings.Builder
	if cfg.TimeFormat != "" {
		b.WriteString(record.Time.Format(cfg.TimeFormat))
		b.WriteByte(' ')
	}
	prefix := "[" + record.Level + "]"
	if cfg.EnableColor {
		prefix = levelColor(record.Level) + prefix + colorReset
	}
	b.WriteString(prefix)
	b.WriteByte(' ')
	b.WriteString(record.Message)
	for key, value := range record.Fields {
		fmt.Fprintf(&b, " %s=%v", key, value)
	}
	b.WriteByte('\n')
	return b.String()
}

func levelColor(name string) string {
	for l := LevelTrace; l <= LevelPanic; l++ {
		if l.String() == name {
			return l.Color()
		}
	}
	return ""
}
