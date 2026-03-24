//go:build !linux && !darwin

package main

import (
	"os/exec"
	"syscall"
)

func childSysProcAttr() *syscall.SysProcAttr {
	return nil
}

func signalWrappedProcess(cmd *exec.Cmd, sig syscall.Signal) error {
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	return cmd.Process.Signal(sig)
}
