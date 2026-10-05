package radius

import (
	"log/slog"
	"sync/atomic"
)

var (
	discardLogger = slog.New(slog.DiscardHandler)
	pkgLogger     atomic.Pointer[slog.Logger]
)

// SetLogger sets the logger for library diagnostics; nil (the default) discards them.
func SetLogger(l *slog.Logger) {
	pkgLogger.Store(l)
}

// logger returns the package logger.
func logger() *slog.Logger {
	if l := pkgLogger.Load(); l != nil {
		return l
	}
	return discardLogger
}
