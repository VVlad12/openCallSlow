package main

import (
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/opencallslow/opencallslow/internal/capture"
	"github.com/opencallslow/opencallslow/internal/enrich"
	"github.com/opencallslow/opencallslow/internal/proc"
)

// checkHandler counts what the capture delivers, without touching the database.
type checkHandler struct {
	names *proc.Names
	dns   *enrich.DNSMap

	mu      sync.Mutex
	packets int
	dnsHits int
	flows   map[checkKey]*[2]uint64
}

type checkKey struct {
	pid    uint32
	remote netip.Addr
}

func (h *checkHandler) OnPacket(p capture.Packet) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.packets++
	k := checkKey{p.PID, p.Remote}
	f := h.flows[k]
	if f == nil {
		f = new([2]uint64)
		h.flows[k] = f
	}
	if p.Inbound {
		f[0] += uint64(p.Bytes)
	} else {
		f[1] += uint64(p.Bytes)
	}
}

func (h *checkHandler) OnDNS(d capture.DNSAnswer) {
	h.mu.Lock()
	h.dnsHits++
	h.mu.Unlock()
	h.dns.Add(d.PID, d.Name, d.Addrs)
}

// check captures for d and logs a diagnostic summary.
func check(log *slog.Logger, dataDir string, d time.Duration) error {
	dns := enrich.NewDNSMap()
	enr, err := enrich.New(dns)
	if err != nil {
		return err
	}
	if db, err := enrich.LoadIPDB(filepath.Join(dataDir, enrich.IPDBFile)); err == nil {
		enr.SetIPDB(db)
	}
	for _, a := range capture.SeedDNS() {
		dns.Add(a.PID, a.Name, a.Addrs)
	}
	log.Info("check: resolver cache", "addresses", dns.Len())

	h := &checkHandler{names: proc.NewNames(), dns: dns, flows: make(map[checkKey]*[2]uint64)}
	sess, err := capture.Start(h, log)
	if err != nil {
		return err
	}
	log.Info("check: capturing — use the network (open a web page, play a video)", "seconds", d.Seconds())
	time.Sleep(d)
	stats := sess.Stats()
	if err := sess.Stop(); err != nil {
		log.Warn("check: stop capture", "err", err)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	log.Info("check: summary", "etwEvents", stats.Events, "lostEvents", stats.LostEvents,
		"packets", h.packets, "dnsAnswers", h.dnsHits, "flows", len(h.flows),
		"frames", stats.PacketFrames, "namesFromPackets", stats.PacketNames, "framesLost", stats.PacketLost)

	type row struct {
		k       checkKey
		in, out uint64
	}
	var rows []row
	for k, f := range h.flows {
		rows = append(rows, row{k, f[0], f[1]})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].in+rows[i].out > rows[j].in+rows[j].out })
	for i, r := range rows {
		if i == 15 {
			break
		}
		at := enr.Attribute(r.k.pid, r.k.remote)
		log.Info("check: flow",
			"app", h.names.Name(r.k.pid), "remote", r.k.remote, "service", at.Service, "site", at.Site,
			"org", at.Org, "country", at.Country, "in", r.in, "out", r.out)
	}
	if h.packets == 0 {
		fmt.Fprintln(os.Stderr, "\nNo traffic was captured. Please share the log file with the developers.")
	}
	return nil
}
