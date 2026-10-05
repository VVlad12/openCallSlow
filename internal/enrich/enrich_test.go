package enrich

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestAttributeByDomain(t *testing.T) {
	dns := NewDNSMap()
	e, err := New(dns)
	if err != nil {
		t.Fatal(err)
	}
	video := netip.MustParseAddr("142.250.1.1")
	search := netip.MustParseAddr("142.250.1.2")
	dns.Add(100, "rr3---sn-4g5e6nsz.googlevideo.com", []netip.Addr{video})
	dns.Add(100, "www.google.com", []netip.Addr{search})
	dns.Add(200, "mail.google.com", []netip.Addr{search})

	cases := []struct {
		pid      uint32
		addr     netip.Addr
		site     string
		service  string
		category string
	}{
		{100, video, "googlevideo.com", "YouTube", "Video streaming"},
		{100, search, "google.com", "Google Search", "Search & web"},
		{200, search, "google.com", "Gmail", "Email & office"}, // same IP, other process
		{300, search, "google.com", "Gmail", "Email & office"}, // unknown process: latest name
	}
	for _, c := range cases {
		at := e.Attribute(c.pid, c.addr)
		if at.Site != c.site || at.Service != c.service || at.Category != c.category || at.Scope != ScopeInternet {
			t.Errorf("pid %d %s: got %+v", c.pid, c.addr, at)
		}
	}

	if at := e.Attribute(1, netip.MustParseAddr("192.168.1.20")); at.Scope != ScopeLAN {
		t.Errorf("LAN address: got %+v", at)
	}
	if at := e.Attribute(1, netip.MustParseAddr("203.0.113.9")); at.Category != CategoryUnattributed || at.RemoteIP == "" {
		t.Errorf("unknown address: got %+v", at)
	}
	if at := e.Attribute(1, netip.MustParseAddr("142.250.1.1")); at.Service != "YouTube" {
		t.Errorf("unknown site fallback: got %+v", at)
	}
}

func TestUnknownDomainUsesSite(t *testing.T) {
	dns := NewDNSMap()
	e, _ := New(dns)
	a := netip.MustParseAddr("198.51.100.7")
	dns.Add(1, "static.example.co.uk", []netip.Addr{a})
	at := e.Attribute(1, a)
	if at.Site != "example.co.uk" || at.Service != "example.co.uk" || at.Category != CategoryOther {
		t.Errorf("got %+v", at)
	}
}

// TestIPDB runs against a downloaded dataset: set OCS_IPDB to its path.
func TestIPDB(t *testing.T) {
	path := os.Getenv("OCS_IPDB")
	if path == "" {
		path = filepath.Join(os.TempDir(), "ocs-test", IPDBFile)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skip("no IP database at", path)
	}
	db, err := LoadIPDB(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d ranges, %d operators", db.Ranges(), len(db.infos))
	for addr, want := range map[string]uint32{
		"8.8.8.8":              15169, // Google
		"1.1.1.1":              13335, // Cloudflare
		"2001:4860:4860::8888": 15169,
	} {
		info, ok := db.Lookup(netip.MustParseAddr(addr))
		if !ok || info.ASN != want {
			t.Errorf("%s: got %+v %v, want AS%d", addr, info, ok, want)
		}
	}
}
