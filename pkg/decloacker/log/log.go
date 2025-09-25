package log

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
)

const (
	PLAIN = "plain"
	JSON  = "json"
	TEXT  = "text"
)

const (
	DEBUG     = slog.LevelDebug
	OK        = slog.LevelInfo - 1
	INFO      = slog.LevelInfo
	WARN      = slog.LevelWarn
	ERROR     = slog.LevelError
	DETECTION = slog.LevelError + 4
	QUIET     = slog.LevelError + 9000
)

var (
	logLevelMap = map[string]slog.Level{
		"debug":     DEBUG,
		"info":      INFO,
		"warn":      WARN,
		"error":     ERROR,
		"detection": DETECTION,
	}
	logLevelTag = map[slog.Level]string{
		DEBUG:     "[d] ",
		OK:        "[\u2713] ",
		INFO:      "[i] ",
		WARN:      "[w] ",
		ERROR:     "[e] ",
		DETECTION: "",
	}
	logLevelColor = map[slog.Level]string{
		DEBUG:     lightGray + logLevelTag[DEBUG] + reset,
		OK:        green + logLevelTag[OK] + reset,
		INFO:      blue + logLevelTag[INFO] + reset,
		WARN:      yellow + logLevelTag[WARN] + reset,
		ERROR:     blue + logLevelTag[ERROR] + reset,
		DETECTION: green + logLevelTag[DETECTION] + reset,
	}
)

var (
	LogLevel  = INFO
	LogFormat = PLAIN
	logger    = &log.Logger{}
	slogger   = &slog.Logger{}
)

func NewLogger(format string) {

	switch format {
	case JSON:
		LogFormat = JSON
		slogger = slog.New(slog.NewJSONHandler(os.Stdout, nil))
		slog.SetDefault(slogger)
	case TEXT:
		LogFormat = TEXT
		slogger = slog.New(slog.NewTextHandler(os.Stdout, nil))
		slog.SetDefault(slogger)
	default:
		slogger = slog.New(&SimpleHandler{level: slog.LevelDebug})
		slog.SetDefault(slogger)
		LogFormat = PLAIN
	}
}

func SetLogLevel(level string) {
	LogLevel = logLevelMap[level]
}

func Log(msg string, args ...any) {
	if LogLevel >= DETECTION {
		return
	}

	if LogFormat == PLAIN {
		slogger.Log(context.Background(), slog.LevelInfo, fmt.Sprintf(msg, args...))
	} else if LogFormat == TEXT {
		if len(args) < 1 {
			return
		}
		slogger.Log(context.Background(), slog.LevelInfo, "", args[1:]...)
	} else if LogFormat == JSON {
		if len(args) < 1 {
			return
		}
		slogger.Log(context.Background(), slog.LevelInfo, "", args[1:]...)
	}
}

func Separator() {
	Log("---------------------------------------8<---------------------------------------\n")
}

func Debug(msg string, args ...any) {
	if LogLevel <= DEBUG {
		fmt.Fprintf(os.Stderr, logLevelColor[DEBUG]+msg, args...)
	}
}

func Ok(msg string, args ...any) {
	if LogLevel <= INFO {
		fmt.Fprintf(os.Stderr, logLevelColor[OK]+msg, args...)
	}
}
func Info(msg string, args ...any) {
	if LogLevel <= INFO {
		fmt.Fprintf(os.Stderr, logLevelColor[INFO]+msg, args...)
	}
}

func Warn(msg string, args ...any) {
	if LogLevel <= WARN {
		fmt.Fprintf(os.Stderr, logLevelColor[WARN]+msg, args...)
	}
}

func Error(msg string, args ...any) {
	if LogLevel <= ERROR {
		fmt.Fprintf(os.Stderr, logLevelColor[ERROR]+msg, args...)
	}
}

func Detection(msg string, args ...any) {
	if LogLevel <= DETECTION {
		fmt.Fprintf(os.Stderr, logLevelColor[DETECTION]+msg, args...)
	}
}
