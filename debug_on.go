//go:build debug
// +build debug

package main

import (
	"fmt"
	"os"
	"time"
)

var debugEnabled = true

// debugPrintf prints debug messages with timestamp when debug mode is enabled
func debugPrintf(format string, args ...interface{}) {
	timestamp := time.Now().Format("15:04:05.000")
	msg := fmt.Sprintf(format, args...)
	fmt.Fprintf(os.Stderr, "[DEBUG %s] %s\n", timestamp, msg)
}

// debugPrintln prints debug messages with timestamp when debug mode is enabled
func debugPrintln(args ...interface{}) {
	timestamp := time.Now().Format("15:04:05.000")
	fmt.Fprintf(os.Stderr, "[DEBUG %s] ", timestamp)
	fmt.Fprintln(os.Stderr, args...)
}