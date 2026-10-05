//go:build windows

package main

import (
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchElevated restarts this program with the same arguments through the
// UAC prompt. The new process opens in its own console window.
func relaunchElevated(extra ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := append(os.Args[1:], extra...)
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = syscall.EscapeArg(a)
	}
	cwd, _ := os.Getwd()
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString(strings.Join(quoted, " "))
	dir, _ := windows.UTF16PtrFromString(cwd)
	return windows.ShellExecute(0, verb, file, params, dir, windows.SW_SHOWNORMAL)
}
