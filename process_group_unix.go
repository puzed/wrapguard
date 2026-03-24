//go:build linux || darwin

package main

import (
	"os/exec"
	"syscall"
)

func childSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

func signalWrappedProcess(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}

	pgid, err := syscall.Getpgid(cmd.Process.Pid)
	if err == nil && pgid > 0 {
		return syscall.Kill(-pgid, sig)
	}

	return cmd.Process.Signal(sig)
}
