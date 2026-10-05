//go:build windows

package srum

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// SnapshotLive copies the in-use SRUDB.dat through a volume shadow copy
// (needs administrator rights) and returns the path of the copy.
func SnapshotLive(dir string) (string, error) {
	root := os.Getenv("SystemRoot")
	if root == "" {
		root = `C:\Windows`
	}
	src := filepath.Join(root, "System32", "sru", "SRUDB.dat")
	dst := filepath.Join(dir, "SRUDB.dat")
	os.Remove(dst)
	out, err := exec.Command(filepath.Join(root, "System32", "esentutl.exe"), "/y", src, "/vss", "/d", dst).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("copy SRUDB.dat (run as administrator): %v: %s", err, strings.TrimSpace(string(out)))
	}
	return dst, nil
}
