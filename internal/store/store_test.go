package store

import (
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSummary(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	base := int64(1_760_000_000) / 60 * 60
	rows := []Row{
		{Minute: base, App: "chrome.exe", Site: "googlevideo.com", Service: "YouTube", Category: "Video streaming", Org: "Google", Country: "US", Proto: "udp", Scope: "internet", BytesIn: 1000, BytesOut: 10},
		{Minute: base + 60, App: "chrome.exe", Site: "google.com", Service: "Google Search", Category: "Search & web", Org: "Google", Country: "US", Proto: "tcp", Scope: "internet", BytesIn: 100, BytesOut: 50},
		{Minute: base + 60, App: "spotify.exe", Site: "scdn.co", Service: "Spotify", Category: "Music & audio", Org: "Fastly", Country: "US", Proto: "tcp", Scope: "internet", BytesIn: 500, BytesOut: 5},
		{Minute: base + 120, App: "svchost.exe", Service: "Local network", Category: "Local network", Org: "Local network", Proto: "udp", Scope: "lan", BytesIn: 7, BytesOut: 3},
	}
	if err := st.InsertTraffic(rows); err != nil {
		t.Fatal(err)
	}

	s, err := st.Summary(base, base+180, 60, 0, Filter{}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if s.Internet.In != 1600 || s.Internet.Out != 65 || s.LAN.In != 7 || s.LAN.Out != 3 {
		t.Errorf("totals: internet %+v lan %+v", s.Internet, s.LAN)
	}
	if len(s.Timeline) != 2 || s.Timeline[1].In != 600 {
		t.Errorf("timeline: %+v", s.Timeline)
	}
	if apps := s.Breakdowns["app"]; len(apps) != 2 || apps[0].Name != "chrome.exe" || apps[0].In != 1100 {
		t.Errorf("apps: %+v", apps)
	}

	s, err = st.Summary(base, base+180, 60, 0, Filter{App: "chrome.exe"}, 10)
	if err != nil {
		t.Fatal(err)
	}
	if svc := s.Breakdowns["service"]; len(svc) != 2 || svc[0].Name != "YouTube" {
		t.Errorf("filtered services: %+v", svc)
	}
}

// TestDemoData fills a database with a plausible day of traffic so the
// dashboard can be previewed without administrator rights:
//
//	OCS_DEMO_DB=/tmp/demo/opencallslow.db go test ./internal/store -run TestDemoData
//	opencallslow serve -data /tmp/demo
func TestDemoData(t *testing.T) {
	path := os.Getenv("OCS_DEMO_DB")
	if path == "" {
		t.Skip("set OCS_DEMO_DB to generate demo data")
	}
	os.MkdirAll(filepath.Dir(path), 0o755)
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	type src struct {
		app, site, service, category, org, country, proto string
		in, out                                           float64 // MB per active minute
		hours                                             [2]int
	}
	sources := []src{
		{"chrome.exe", "googlevideo.com", "YouTube", "Video streaming", "Google", "US", "udp", 18, 0.4, [2]int{20, 23}},
		{"chrome.exe", "google.com", "Google Search", "Search & web", "Google", "US", "tcp", 0.3, 0.05, [2]int{8, 22}},
		{"ms-teams.exe", "teams.microsoft.com", "Microsoft Teams", "Video calls & chat", "Microsoft", "US", "udp", 9, 7, [2]int{10, 11}},
		{"spotify.exe", "scdn.co", "Spotify", "Music & audio", "Fastly", "US", "tcp", 1.2, 0.02, [2]int{9, 17}},
		{"onedrive.exe", "sharepoint.com", "OneDrive & SharePoint", "Cloud storage & sync", "Microsoft", "US", "tcp", 0.5, 2.5, [2]int{8, 18}},
		{"svchost.exe", "windowsupdate.com", "Windows Update", "Software updates", "Akamai", "NL", "tcp", 40, 0.3, [2]int{13, 13}},
		{"chrome.exe", "doubleclick.net", "Google ads & analytics", "Advertising & tracking", "Google", "US", "tcp", 0.2, 0.05, [2]int{8, 22}},
		{"claude.exe", "claude.ai", "Claude / Anthropic", "AI assistants", "Google", "US", "tcp", 0.4, 0.2, [2]int{9, 18}},
		{"chrome.exe", "srf.ch", "SRF / RTS / RSI", "News & info", "Swisscom", "CH", "tcp", 1.5, 0.05, [2]int{7, 8}},
	}
	rng := rand.New(rand.NewSource(1))
	start := time.Now().Add(-48 * time.Hour).Truncate(time.Minute)
	var rows []Row
	for m := start; m.Before(time.Now()); m = m.Add(time.Minute) {
		h := m.Hour()
		for _, s := range sources {
			if h < s.hours[0] || h > s.hours[1] || rng.Float64() < 0.35 {
				continue
			}
			f := 0.3 + rng.Float64()*1.4
			rows = append(rows, Row{Minute: m.Unix(), App: s.app, Site: s.site, Service: s.service, Category: s.category,
				Org: s.org, Country: s.country, Proto: s.proto, Scope: "internet",
				BytesIn: uint64(s.in * f * 1e6), BytesOut: uint64(s.out * f * 1e6)})
		}
		if rng.Float64() < 0.2 {
			rows = append(rows, Row{Minute: m.Unix(), App: "svchost.exe", Service: "Local network", Category: "Local network",
				Org: "Local network", Proto: "udp", Scope: "lan", BytesIn: 20000, BytesOut: 5000})
		}
	}
	if err := st.InsertTraffic(rows); err != nil {
		t.Fatal(err)
	}
	var srum []SrumRow
	for d := 0; d < 30*24; d++ {
		hour := time.Now().Add(-time.Duration(d) * time.Hour).Truncate(time.Hour)
		for _, app := range []string{"chrome.exe", "ms-teams.exe", "onedrive.exe", "spotify.exe", "svchost.exe"} {
			if hour.Hour() < 8 || rng.Float64() < 0.4 {
				continue
			}
			srum = append(srum, SrumRow{Hour: hour.Unix(), App: app, Iface: 1,
				BytesIn: uint64(rng.Float64() * 300e6), BytesOut: uint64(rng.Float64() * 30e6)})
		}
	}
	if err := st.UpsertSrum(srum); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d traffic rows and %d SRUM rows to %s", len(rows), len(srum), path)
}
