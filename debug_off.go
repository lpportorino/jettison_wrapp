//go:build !debug
// +build !debug

package main

var debugEnabled = false

// debugPrintf is a no-op when debug mode is disabled
func debugPrintf(format string, args ...interface{}) {}

// debugPrintln is a no-op when debug mode is disabled
func debugPrintln(args ...interface{}) {}