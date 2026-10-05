//go:build !windows

package main

import (
	"errors"
	"os"
)

func isElevated() bool { return os.Geteuid() == 0 }

func relaunchElevated(...string) error {
	return errors.New("restart with sudo")
}
