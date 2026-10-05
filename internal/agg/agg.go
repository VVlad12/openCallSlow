// Package agg sums capture events into per-minute flows in memory and
// periodically writes them, enriched, to the store. Keeping the hot path to
// a single map update is what keeps the collector light.
package agg

import (
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/opencallslow/opencallslow/internal/capture"
	"github.com/opencallslow/opencallslow/internal/enrich"
	"github.com/opencallslow/opencallslow/internal/proc"
	"github.com/opencallslow/opencallslow/internal/store"
)

type flowKey struct {
	minute int64
	pid    uint32
	remote netip.Addr
	proto  capture.Proto
}

type flow struct {
	app     string
	in, out uint64
}

type Aggregator struct {
	names *proc.Names
	enr   *enrich.Enricher
	st    *store.Store
	log   *slog.Logger

	mu    sync.Mutex
	flows map[flowKey]*flow

	now func() time.Time
}

func New(enr *enrich.Enricher, st *store.Store, log *slog.Logger) *Aggregator {
	return &Aggregator{
		names: proc.NewNames(),
		enr:   enr,
		st:    st,
		log:   log,
		flows: make(map[flowKey]*flow),
		now:   time.Now,
	}
}

func (a *Aggregator) OnPacket(p capture.Packet) {
	if enrich.Skip(p.Remote) {
		return
	}
	k := flowKey{minute: a.now().Unix() / 60 * 60, pid: p.PID, remote: p.Remote, proto: p.Proto}
	a.mu.Lock()
	f, ok := a.flows[k]
	if !ok {
		// Resolve the name while the process is certainly alive. Names are
		// cached, so this is a map lookup in the common case.
		a.mu.Unlock()
		app := a.names.Name(p.PID)
		a.mu.Lock()
		if f, ok = a.flows[k]; !ok {
			f = &flow{app: app}
			a.flows[k] = f
		}
	}
	if p.Inbound {
		f.in += uint64(p.Bytes)
	} else {
		f.out += uint64(p.Bytes)
	}
	a.mu.Unlock()
}

func (a *Aggregator) OnDNS(d capture.DNSAnswer) {
	a.enr.DNS.Add(d.PID, d.Name, d.Addrs)
}

type rowKey struct {
	minute                                                             int64
	app, site, service, category, remoteIP, org, country, proto, scope string
	asn                                                                uint32
}

// Flush writes finished minutes, or everything when all is true (shutdown).
func (a *Aggregator) Flush(all bool) error {
	current := a.now().Unix() / 60 * 60
	a.mu.Lock()
	var done map[flowKey]*flow
	for k, f := range a.flows {
		if all || k.minute < current {
			if done == nil {
				done = make(map[flowKey]*flow)
			}
			done[k] = f
			delete(a.flows, k)
		}
	}
	a.mu.Unlock()
	if len(done) == 0 {
		return nil
	}

	merged := make(map[rowKey]*store.Row)
	for k, f := range done {
		at := a.enr.Attribute(k.pid, k.remote)
		rk := rowKey{k.minute, f.app, at.Site, at.Service, at.Category, at.RemoteIP, at.Org, at.Country, k.proto.String(), at.Scope, at.ASN}
		r, ok := merged[rk]
		if !ok {
			r = &store.Row{Minute: k.minute, App: f.app, Site: at.Site, Service: at.Service, Category: at.Category,
				RemoteIP: at.RemoteIP, ASN: at.ASN, Org: at.Org, Country: at.Country, Proto: k.proto.String(), Scope: at.Scope}
			merged[rk] = r
		}
		r.BytesIn += f.in
		r.BytesOut += f.out
	}
	rows := make([]store.Row, 0, len(merged))
	for _, r := range merged {
		rows = append(rows, *r)
	}
	return a.st.InsertTraffic(rows)
}

// Run flushes every interval until stop is closed, then flushes the rest.
func (a *Aggregator) Run(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	prune := time.NewTicker(time.Hour)
	defer prune.Stop()
	for {
		select {
		case <-stop:
			if err := a.Flush(true); err != nil {
				a.log.Error("final flush failed", "err", err)
			}
			return
		case <-t.C:
			if err := a.Flush(false); err != nil {
				a.log.Error("flush failed", "err", err)
			}
		case <-prune.C:
			a.enr.DNS.Prune(24 * time.Hour)
		}
	}
}
