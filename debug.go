// +build linux

package main

import (
	"fmt"
	"os/exec"
	"strconv"
	"syscall"
	"time"
)

// DebugConfig holds debug session configuration
type DebugConfig struct {
	Enabled bool
	Port    int
	Host    string
}

// startProcessPaused launches the child process with PTRACE_TRACEME,
// causing it to stop immediately after execve (before main runs).
// Returns the *exec.Cmd with PID set.
func startProcessPaused(cmd *exec.Cmd) error {
	// Set ptrace options
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Ptrace = true   // Child does PTRACE_TRACEME
	cmd.SysProcAttr.Setpgid = true  // Isolate process group

	// Start the process
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start process: %w", err)
	}

	debugPrintf("Started process %d with ptrace (paused at first instruction)", cmd.Process.Pid)
	return nil
}

// waitForExecStop waits for the child to stop after execve (SIGTRAP)
func waitForExecStop(pid int) error {
	var st syscall.WaitStatus
	wpid, err := syscall.Wait4(pid, &st, 0, nil)
	if err != nil {
		return fmt.Errorf("wait4 failed: %w", err)
	}
	if wpid != pid {
		return fmt.Errorf("unexpected wait4 pid: got %d, expected %d", wpid, pid)
	}
	if !st.Stopped() {
		return fmt.Errorf("process not stopped after execve: status=%v", st)
	}
	debugPrintf("Process %d stopped after execve (signal: %v)", pid, st.StopSignal())
	return nil
}

// detachAndKeepStopped queues SIGSTOP, waits for it, then detaches
// leaving the process in stopped state for gdbserver to attach
func detachAndKeepStopped(pid int) error {
	// Queue SIGSTOP
	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		return fmt.Errorf("failed to send SIGSTOP: %w", err)
	}

	// Wait for SIGSTOP delivery
	var st syscall.WaitStatus
	_, err := syscall.Wait4(pid, &st, 0, nil)
	if err != nil {
		return fmt.Errorf("wait4 for SIGSTOP failed: %w", err)
	}

	// Detach while process is stopped (leaves it paused)
	if err := syscall.PtraceDetach(pid); err != nil {
		return fmt.Errorf("ptrace detach failed: %w", err)
	}

	debugPrintf("Detached from process %d (remains stopped for gdbserver)", pid)
	return nil
}

// launchGdbserver starts gdbserver attached to the stopped process
func launchGdbserver(pid int, host string, port int) (*exec.Cmd, error) {
	addr := fmt.Sprintf("%s:%d", host, port)

	// gdbserver 127.0.0.1:2345 --attach <pid>
	gdbCmd := exec.Command("gdbserver", addr, "--attach", strconv.Itoa(pid))

	// Capture gdbserver output for debugging
	// You can redirect to a logger if needed
	gdbCmd.Stdout = nil
	gdbCmd.Stderr = nil

	if err := gdbCmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start gdbserver: %w", err)
	}

	// Give gdbserver a moment to attach and start listening
	time.Sleep(200 * time.Millisecond)

	debugPrintf("gdbserver started on %s (PID: %d)", addr, gdbCmd.Process.Pid)
	return gdbCmd, nil
}

// setupDebugSession orchestrates the entire debug setup:
// 1. Start process paused (ptrace)
// 2. Wait for execve stop
// 3. Detach while keeping stopped
// 4. Launch gdbserver
// Returns gdbserver command (to wait on later) or error
func setupDebugSession(cmd *exec.Cmd, config DebugConfig) (*exec.Cmd, error) {
	debugPrintf("Setting up debug session on %s:%d", config.Host, config.Port)

	// 1. Start paused
	if err := startProcessPaused(cmd); err != nil {
		return nil, err
	}
	pid := cmd.Process.Pid

	// 2. Wait for execve stop
	if err := waitForExecStop(pid); err != nil {
		syscall.Kill(pid, syscall.SIGKILL) // Cleanup on failure
		return nil, err
	}

	// 3. Detach while stopped
	if err := detachAndKeepStopped(pid); err != nil {
		syscall.Kill(pid, syscall.SIGKILL)
		return nil, err
	}

	// 4. Launch gdbserver
	gdbCmd, err := launchGdbserver(pid, config.Host, config.Port)
	if err != nil {
		syscall.Kill(pid, syscall.SIGKILL)
		return nil, err
	}

	return gdbCmd, nil
}

// getDebugConnectionInfo returns connection instructions for the user/logs
func getDebugConnectionInfo(config DebugConfig, executable string) string {
	return fmt.Sprintf(`
╔═══════════════════════════════════════════════════════════════╗
║  DEBUG MODE ACTIVE - Process paused at first instruction     ║
╠═══════════════════════════════════════════════════════════════╣
║  gdbserver listening on: %s:%-5d
║
║  To connect from GDB:
║    gdb %s
║    (gdb) target remote %s:%d
║    (gdb) break main
║    (gdb) continue
║
║  To connect from CLion:
║    Run → Edit Configurations → + → Remote GDB Server
║    'target remote' args: %s:%d
║    Symbol file: %s
║
║  Process will start when debugger connects and continues
╚═══════════════════════════════════════════════════════════════╝
`, config.Host, config.Port, executable, config.Host, config.Port,
   config.Host, config.Port, executable)
}
