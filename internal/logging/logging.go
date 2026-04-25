// Package logging configures the project's slog logger.
package logging

import (
	"log/slog"
	"os"
)

// New returns a JSON slog.Logger at the given level (parsed from "debug",
// "info", "warn", "error" — defaults to info on parse error).
func New(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	h := slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl})
	return slog.New(h)
}
