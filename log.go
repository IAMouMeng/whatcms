package main

import (
	"log"
	"os"
)

var (
	infoLogger  *log.Logger
	errorLogger *log.Logger
)

func init() {
	infoLogger = log.New(os.Stdout, "INFO: ", log.Ldate|log.Ltime|log.Lshortfile)
	errorLogger = log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Lshortfile)
}

func HandleError(err error, msg string) {
	if err != nil {
		errorLogger.Printf("%s %v", msg, err)
	}
}

func HandleLog(msg string) {
	infoLogger.Println(msg)
}
