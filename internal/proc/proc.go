// Package proc maps process IDs to executable names, with a short-lived
// cache so the capture hot path rarely touches the OS.
package proc

import (
	"strconv"
	"sync"
	"time"
)

const ttl = 2 * time.Minute

type entry struct {
	name    string
	checked time.Time
}

type Names struct {
	mu    sync.Mutex
	cache map[uint32]entry
}

func NewNames() *Names {
	return &Names{cache: make(map[uint32]entry)}
}

// Name returns the executable name (e.g. "chrome.exe") for pid. Process IDs
// are reused by the OS, so entries expire after a couple of minutes.
func (n *Names) Name(pid uint32) string {
	now := time.Now()
	n.mu.Lock()
	e, ok := n.cache[pid]
	n.mu.Unlock()
	if ok && now.Sub(e.checked) < ttl {
		return e.name
	}
	name := lookup(pid)
	if name == "" {
		if ok {
			// Process has exited since we last saw it: keep the old name.
			name = e.name
		} else {
			name = "pid " + strconv.FormatUint(uint64(pid), 10)
		}
	}
	n.mu.Lock()
	n.cache[pid] = entry{name: name, checked: now}
	if len(n.cache) > 4096 {
		for k, v := range n.cache {
			if now.Sub(v.checked) > ttl {
				delete(n.cache, k)
			}
		}
	}
	n.mu.Unlock()
	return name
}
