//go:build windows

package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/0xrawsec/golang-etw/etw"
)

// sessionName is the ETW session we own. A stale session left by a crash
// is stopped and recreated by etw.RealTimeSession.Start.
const sessionName = "openCallSlow"

const (
	kernelNetworkGUID = "{7DD42A49-5329-4832-8DFD-43D979153A88}" // Microsoft-Windows-Kernel-Network
	dnsClientGUID     = "{1C95126E-7EEA-49A9-A3FE-A378B03DDB4D}" // Microsoft-Windows-DNS-Client

	dnsQueryCompleted = 3008
)

var (
	kernelNetwork = etw.MustParseGUIDFromString(kernelNetworkGUID)
	dnsClient     = etw.MustParseGUIDFromString(dnsClientGUID)
)

// Kernel-Network send/receive events. All share the payload prefix
// PID u32, size u32, daddr, saddr, dport u16be, sport u16be.
var netEventIDs = []uint16{10, 11, 26, 27, 42, 43, 58, 59}

func netEventKind(id uint16) (v6, udp, inbound, ok bool) {
	switch id {
	case 10:
		return false, false, false, true
	case 11:
		return false, false, true, true
	case 26:
		return true, false, false, true
	case 27:
		return true, false, true, true
	case 42:
		return false, true, false, true
	case 43:
		return false, true, true, true
	case 58:
		return true, true, false, true
	case 59:
		return true, true, true, true
	}
	return
}

type rawNet struct {
	pid          uint32
	size         uint32
	daddr, saddr netip.Addr
	dport, sport uint16
}

// decodeNet reads a Kernel-Network payload directly. Decoding through TDH
// for every packet would cost far more than the rest of the pipeline.
func decodeNet(er *etw.EventRecord) (r rawNet, v6, udp, inbound, ok bool) {
	if v6, udp, inbound, ok = netEventKind(er.EventHeader.EventDescriptor.Id); !ok {
		return
	}
	alen := 4
	if v6 {
		alen = 16
	}
	n := int(er.UserDataLength)
	if er.UserData == 0 || n < 8+2*alen+4 {
		ok = false
		return
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(er.UserData)), n)
	r.pid = binary.LittleEndian.Uint32(data[0:])
	r.size = binary.LittleEndian.Uint32(data[4:])
	r.daddr = addrFrom(data[8 : 8+alen])
	r.saddr = addrFrom(data[8+alen : 8+2*alen])
	off := 8 + 2*alen
	r.dport = binary.BigEndian.Uint16(data[off:])
	r.sport = binary.BigEndian.Uint16(data[off+2:])
	return
}

func addrFrom(b []byte) netip.Addr {
	if len(b) == 4 {
		return netip.AddrFrom4([4]byte(b))
	}
	return netip.AddrFrom16([16]byte(b)).Unmap()
}

type winSession struct {
	sess   *etw.RealTimeSession
	cons   *etw.Consumer
	cancel context.CancelFunc
	events atomic.Uint64
	pkts   *packetSession // optional: names learned from packets
}

func start(h Handler, log *slog.Logger) (Session, error) {
	s := etw.NewRealTimeSession(sessionName)
	if err := s.Start(); err != nil {
		return nil, fmt.Errorf("start ETW session (run as administrator): %w", err)
	}
	if err := enable(s, log, etw.Provider{
		GUID:            kernelNetworkGUID,
		Name:            "Microsoft-Windows-Kernel-Network",
		EnableLevel:     0xff,
		MatchAnyKeyword: 0x30, // IPv4 | IPv6
		Filter:          netEventIDs,
	}); err != nil {
		s.Stop()
		return nil, err
	}
	if err := enable(s, log, etw.Provider{
		GUID:            dnsClientGUID,
		Name:            "Microsoft-Windows-DNS-Client",
		EnableLevel:     0xff,
		MatchAnyKeyword: 0xffffffffffffffff,
		Filter:          []uint16{dnsQueryCompleted},
	}); err != nil {
		s.Stop()
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	locals := watchLocalAddrs(ctx)
	ws := &winSession{sess: s, cancel: cancel}
	c := etw.NewRealTimeConsumer(ctx)
	c.FromSessions(s)
	ws.cons = c

	// Callbacks run on the single ProcessTrace thread, so this needs no lock.
	verified := make(map[uint16]int)

	c.EventRecordCallback = func(er *etw.EventRecord) bool {
		switch {
		case er.EventHeader.ProviderId.Equals(kernelNetwork):
			ws.events.Add(1)
			r, _, udp, inbound, ok := decodeNet(er)
			if !ok {
				return false
			}
			remote, rport := r.daddr, r.dport
			if locals.has(remote) && !locals.has(r.saddr) {
				remote, rport = r.saddr, r.sport
			}
			p := Packet{PID: r.pid, Proto: TCP, Remote: remote, RemotePort: rport, Bytes: r.size, Inbound: inbound}
			if udp {
				p.Proto = UDP
			}
			h.OnPacket(p)
			// Let the first few events of each kind go through TDH so the
			// hand-written decoder is checked against the provider manifest.
			id := er.EventHeader.EventDescriptor.Id
			if verified[id] < 2 {
				verified[id]++
				return true
			}
			return false
		case er.EventHeader.ProviderId.Equals(dnsClient):
			ws.events.Add(1)
			return er.EventHeader.EventDescriptor.Id == dnsQueryCompleted
		}
		return false
	}

	c.PreparedCallback = func(eh *etw.EventRecordHelper) error {
		if eh.EventRec.EventHeader.ProviderId.Equals(kernelNetwork) {
			checkLayout(eh, log)
			eh.Skip()
		}
		return nil
	}

	c.EventCallback = func(e *etw.Event) error {
		name, _ := e.GetPropertyString("QueryName")
		status, _ := e.GetPropertyString("QueryStatus")
		results, _ := e.GetPropertyString("QueryResults")
		if name == "" || (status != "" && status != "0") {
			return nil
		}
		if addrs := parseQueryResults(results); len(addrs) > 0 {
			h.OnDNS(DNSAnswer{PID: e.System.Execution.ProcessID, Name: normalizeName(name), Addrs: addrs})
		}
		return nil
	}

	if err := c.Start(); err != nil {
		cancel()
		s.Stop()
		return nil, fmt.Errorf("start ETW consumer: %w", err)
	}
	if ps, err := startPackets(h, log); err != nil {
		log.Warn("packet-based name detection unavailable; domains rely on Windows DNS only", "err", err)
	} else {
		ws.pkts = ps
		log.Info("packet-based name detection running (DNS responses and TLS server names only)")
	}
	return ws, nil
}

// enable turns on a provider with kernel-side event-ID filtering, and falls
// back to no filter when the provider rejects it (some Windows builds answer
// "The parameter is incorrect"); the callbacks ignore unwanted events anyway.
func enable(s *etw.RealTimeSession, log *slog.Logger, p etw.Provider) error {
	err := s.EnableProvider(p)
	if err == nil {
		log.Debug("ETW provider enabled", "provider", p.Name, "eventFilter", true)
		return nil
	}
	if len(p.Filter) == 0 {
		return fmt.Errorf("enable %s: %w", p.Name, err)
	}
	log.Info("ETW provider rejected event filter, enabling without it", "provider", p.Name, "err", err)
	p.Filter = nil
	if err := s.EnableProvider(p); err != nil {
		return fmt.Errorf("enable %s: %w", p.Name, err)
	}
	return nil
}

func (w *winSession) Stats() Stats {
	s := Stats{Events: w.events.Load(), LostEvents: uint64(w.cons.LostEvents)}
	if w.pkts != nil {
		s.PacketFrames, s.PacketNames = w.pkts.frames.Load(), w.pkts.names.Load()
		s.PacketLost = uint64(w.pkts.cons.LostEvents)
	}
	return s
}

func (w *winSession) Stop() error {
	if w.pkts != nil {
		w.pkts.Stop()
	}
	w.cancel()
	err := w.cons.Stop()
	if serr := w.sess.Stop(); err == nil {
		err = serr
	}
	return err
}

// checkLayout compares decodeNet with the TDH decoding of the same event
// and logs the outcome once per event ID.
func checkLayout(eh *etw.EventRecordHelper, log *slog.Logger) {
	r, _, _, _, ok := decodeNet(eh.EventRec)
	id := eh.EventRec.EventHeader.EventDescriptor.Id
	if !ok {
		log.Warn("ETW layout check: payload too short", "event", id)
		return
	}
	pid, _ := eh.GetPropertyUint("PID")
	size, _ := eh.GetPropertyUint("size")
	dport, _ := eh.GetPropertyUint("dport")
	daddrS, _ := eh.GetPropertyString("daddr")
	daddr, _ := netip.ParseAddr(strings.Trim(daddrS, "[]"))
	if uint32(pid) == r.pid && uint32(size) == r.size && uint16(dport) == r.dport && daddr.Unmap() == r.daddr {
		log.Debug("ETW layout check ok", "event", id)
		return
	}
	log.Warn("ETW layout check mismatch — traffic numbers may be wrong",
		"event", id,
		"tdh", fmt.Sprintf("pid=%d size=%d daddr=%s dport=%d", pid, size, daddrS, dport),
		"raw", fmt.Sprintf("pid=%d size=%d daddr=%s dport=%d", r.pid, r.size, r.daddr, r.dport))
}

// parseQueryResults extracts addresses from the DNS-Client QueryResults
// field, e.g. "type:  5 www.l.google.com;::ffff:142.250.180.4;".
func parseQueryResults(s string) []netip.Addr {
	var out []netip.Addr
	for _, tok := range strings.Split(s, ";") {
		tok = strings.TrimSpace(tok)
		if tok == "" || strings.HasPrefix(tok, "type:") {
			continue
		}
		if a, err := netip.ParseAddr(tok); err == nil {
			out = append(out, a.Unmap())
		}
	}
	return out
}

// localAddrs tracks this machine's interface addresses so we can tell the
// remote end of a connection apart from the local one.
type localAddrs struct {
	set atomic.Pointer[map[netip.Addr]struct{}]
}

func (l *localAddrs) has(a netip.Addr) bool {
	_, ok := (*l.set.Load())[a]
	return ok
}

func watchLocalAddrs(ctx context.Context) *localAddrs {
	l := &localAddrs{}
	refresh := func() {
		m := make(map[netip.Addr]struct{})
		if addrs, err := net.InterfaceAddrs(); err == nil {
			for _, a := range addrs {
				if p, err := netip.ParsePrefix(a.String()); err == nil {
					m[p.Addr().Unmap()] = struct{}{}
				}
			}
		}
		l.set.Store(&m)
	}
	refresh()
	go func() {
		t := time.NewTicker(30 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				refresh()
			}
		}
	}()
	return l
}
