package logger

import (
	"time"

	ds "github.com/SolarResearchTeam/dn-sniffer/datastructures"
	"github.com/SolarResearchTeam/dn-sniffer/webserver/models"
)

func WriteLog(log *ds.Log) {
	log.Time = time.Now().Format("2006-01-02 15:04:05")
	models.Database.AddLog(log)
}

// Debug logs a debug message
func Debug(source string, message string) {
	log := ds.Log{Source:source, Level:"Debug", Message:message}
	WriteLog(&log)
	Console_Debugf("%s: %s",source,message)
}

// Info logs an informational message
func Info(source string, message string) {
	log := ds.Log{Source:source, Level:"Info", Message:message}
	WriteLog(&log)
	Console_Infof("%s: %s",source,message)
}

// Error logs an error message
func Error(source string, message string) {
	log := ds.Log{Source:source, Level:"Error", Message:message}
	WriteLog(&log)
	Console_Errorf("%s: %s",source,message)
}

// Warn logs a warning message
func Warn(source string, message string) {
	log := ds.Log{Source:source, Level:"Warn", Message:message}
	WriteLog(&log)
	Console_Warnf("%s: %s",source,message)
}

// Fatal logs a fatal error message
func Fatal(source string, message string) {
	log := ds.Log{Source:source, Level:"Fatal", Message:message}
	WriteLog(&log)
	Console_Fatalf("%s: %s",source,message)
}
