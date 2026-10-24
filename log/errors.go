package log

import "errors"

var (
	ErrInvalidLevel  = errors.New("log: invalid level")
	ErrInvalidFormat = errors.New("log: invalid format")
	ErrWriteFailed   = errors.New("log: failed to write log record")
)
