package log


import (
	"log/slog"
	"os"
)


var Logger *slog.Logger

type Mode int

const (
	Dev Mode = iota
	Prod
)

func Init(mode Mode, debug bool) {
	var handler slog.Handler;

	opts := &slog.HandlerOptions{}
	if debug {
		opts.Level = slog.LevelDebug
	}

	switch mode {
	case Dev:
		handler = slog.NewTextHandler(os.Stderr, opts)
	case Prod:
		handler = slog.NewJSONHandler(os.Stderr, opts)
	default:
		handler = slog.NewTextHandler(os.Stderr, opts)
	}

	Logger = slog.New(handler)
}
