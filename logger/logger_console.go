package logger

import (
	"io"
	"os"
	"log"

	"github.com/sirupsen/logrus"
)

var Logger *logrus.Logger
var NoopLogger *log.Logger

type noopLogger struct {

}

func (l *noopLogger) Write(p []byte) (n int, err error) {
	return 0, nil
}


func init() {
	Logger = logrus.New()
	Logger.SetOutput(os.Stdout)
	Logger.SetLevel(logrus.DebugLevel)
	Logger.Formatter = &logrus.TextFormatter{DisableColors: false,FullTimestamp: true,}

	NoopLogger = log.New(&noopLogger{}, "", 0)
}

func New(args ...interface{}) *log.Logger {
	return log.New(os.Stdout, "", 0)
}

// Debug logs a debug message
func Console_Debug(args ...interface{}) {
	Logger.Debug(args...)
}

// Debugf logs a formatted debug messsage
func Console_Debugf(format string, args ...interface{}) {
	Logger.Debugf(format, args...)
}

// Info logs an informational message
func Console_Info(args ...interface{}) {
	Logger.Info(args...)
}

// Infof logs a formatted informational message
func Console_Infof(format string, args ...interface{}) {
	Logger.Infof(format, args...)
}

// Error logs an error message
func Console_Error(args ...interface{}) {
	Logger.Error(args...)
}

// Errorf logs a formatted error message
func Console_Errorf(format string, args ...interface{}) {
	Logger.Errorf(format, args...)
}

// Warn logs a warning message
func Console_Warn(args ...interface{}) {
	Logger.Warn(args...)
}

// Warnf logs a formatted warning message
func Console_Warnf(format string, args ...interface{}) {
	Logger.Warnf(format, args...)
}

// Fatal logs a fatal error message
func Console_Fatal(args ...interface{}) {
	Logger.Fatal(args...)
}

// Fatalf logs a formatted fatal error message
func Console_Fatalf(format string, args ...interface{}) {
	Logger.Fatalf(format, args...)
}

// WithFields returns a new log enty with the provided fields
func Console_WithFields(fields logrus.Fields) *logrus.Entry {
	return Logger.WithFields(fields)
}

// Writer returns the current logging writer
func Console_Writer() *io.PipeWriter {
	return Logger.Writer()
}