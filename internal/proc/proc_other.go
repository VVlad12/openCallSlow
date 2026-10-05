//go:build !windows

package proc

import (
	"os"
	"strconv"
	"strings"
)

func lookup(pid uint32) string {
	// Linux; other platforms simply fall back to "pid N".
	b, err := os.ReadFile("/proc/" + strconv.FormatUint(uint64(pid), 10) + "/comm")
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(string(b)))
}
