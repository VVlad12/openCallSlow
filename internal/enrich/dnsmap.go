package enrich

import (
	"net/netip"
	"sync"
	"time"
)

// maxNamesPerAddr bounds how many names we remember for one address. Large
// CDNs serve many domains from the same IPs.
const maxNamesPerAddr = 6

type dnsName struct {
	name string
	pid  uint32
	at   time.Time
}

// DNSMap remembers which domain names resolved to which addresses, so a
// connection to an IP can be labelled with the name the program asked for.
type DNSMap struct {
	mu     sync.Mutex
	byAddr map[netip.Addr][]dnsName
}

func NewDNSMap() *DNSMap {
	return &DNSMap{byAddr: make(map[netip.Addr][]dnsName)}
}

func (m *DNSMap) Add(pid uint32, name string, addrs []netip.Addr) {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, a := range addrs {
		names := m.byAddr[a]
		// Drop a previous entry for the same name so the list stays ordered
		// by recency.
		for i := 0; i < len(names); i++ {
			if names[i].name == name && names[i].pid == pid {
				names = append(names[:i], names[i+1:]...)
				break
			}
		}
		names = append(names, dnsName{name: name, pid: pid, at: now})
		if len(names) > maxNamesPerAddr {
			names = names[len(names)-maxNamesPerAddr:]
		}
		m.byAddr[a] = names
	}
}

// Lookup returns the most likely name for traffic from pid to a: the latest
// name that same process resolved to a, else the latest name anyone did.
func (m *DNSMap) Lookup(pid uint32, a netip.Addr) string {
	m.mu.Lock()
	defer m.mu.Unlock()
	names := m.byAddr[a]
	for i := len(names) - 1; i >= 0; i-- {
		if names[i].pid == pid {
			return names[i].name
		}
	}
	if len(names) > 0 {
		return names[len(names)-1].name
	}
	return ""
}

// Prune forgets mappings not refreshed within maxAge.
func (m *DNSMap) Prune(maxAge time.Duration) {
	cutoff := time.Now().Add(-maxAge)
	m.mu.Lock()
	defer m.mu.Unlock()
	for a, names := range m.byAddr {
		kept := names[:0]
		for _, n := range names {
			if n.at.After(cutoff) {
				kept = append(kept, n)
			}
		}
		if len(kept) == 0 {
			delete(m.byAddr, a)
		} else {
			m.byAddr[a] = kept
		}
	}
}

func (m *DNSMap) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.byAddr)
}
