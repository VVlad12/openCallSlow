package capture

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// wireNames learns name→address mappings from raw packets: DNS responses
// (for programs that resolve names themselves, like Chrome) and the server
// name (SNI) in TLS ClientHello messages. Nothing else in a packet is read.
type wireNames struct {
	mu      sync.Mutex
	pending map[flow4]*partialHello // ClientHellos split over TCP segments
}

type flow4 struct {
	src, dst         netip.Addr
	srcPort, dstPort uint16
}

type partialHello struct {
	buf  []byte
	want int
	at   time.Time
}

const maxPendingHellos = 256

func newWireNames() *wireNames {
	return &wireNames{pending: make(map[flow4]*partialHello)}
}

// frame inspects one link-layer frame (Ethernet, or raw IP for some
// adapters) and returns any names learned from it.
func (w *wireNames) frame(b []byte) []DNSAnswer {
	l3, ok := ipPayloadStart(b)
	if !ok {
		return nil
	}
	src, dst, proto, payload, ok := parseIP(l3)
	if !ok {
		return nil
	}
	switch proto {
	case 17: // UDP
		if len(payload) < 8 {
			return nil
		}
		if binary.BigEndian.Uint16(payload[0:2]) == 53 {
			return parseDNSResponse(payload[8:])
		}
	case 6: // TCP
		if len(payload) < 20 {
			return nil
		}
		off := int(payload[12]>>4) * 4
		if off < 20 || off > len(payload) {
			return nil
		}
		data := payload[off:]
		if len(data) == 0 {
			return nil
		}
		k := flow4{src, dst, binary.BigEndian.Uint16(payload[0:2]), binary.BigEndian.Uint16(payload[2:4])}
		if name := w.tlsHello(k, data); name != "" {
			return []DNSAnswer{{Name: name, Addrs: []netip.Addr{dst}}}
		}
	}
	return nil
}

func ipPayloadStart(b []byte) ([]byte, bool) {
	if len(b) >= 14 {
		et := binary.BigEndian.Uint16(b[12:14])
		off := 14
		if et == 0x8100 && len(b) >= 18 { // VLAN tag
			et = binary.BigEndian.Uint16(b[16:18])
			off = 18
		}
		if et == 0x0800 || et == 0x86DD {
			return b[off:], true
		}
	}
	if len(b) > 0 && (b[0]>>4 == 4 || b[0]>>4 == 6) {
		return b, true // raw IP (no link-layer header)
	}
	return nil, false
}

func parseIP(b []byte) (src, dst netip.Addr, proto byte, payload []byte, ok bool) {
	if len(b) < 20 {
		return
	}
	switch b[0] >> 4 {
	case 4:
		ihl := int(b[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(b[2:4]))
		if ihl < 20 || total < ihl || len(b) < ihl {
			return
		}
		if binary.BigEndian.Uint16(b[6:8])&0x1fff != 0 {
			return // not the first fragment
		}
		if total > len(b) {
			total = len(b)
		}
		return netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), b[9], b[ihl:total], true
	case 6:
		if len(b) < 40 {
			return
		}
		src = netip.AddrFrom16([16]byte(b[8:24])).Unmap()
		dst = netip.AddrFrom16([16]byte(b[24:40])).Unmap()
		next, rest := b[6], b[40:]
		// Skip the common extension headers.
		for next == 0 || next == 43 || next == 60 {
			if len(rest) < 8 {
				return
			}
			n := (int(rest[1]) + 1) * 8
			if n > len(rest) {
				return
			}
			next, rest = rest[0], rest[n:]
		}
		return src, dst, next, rest, true
	}
	return
}

// parseDNSResponse maps every A/AAAA answer to the name that was asked.
func parseDNSResponse(msg []byte) []DNSAnswer {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil || !h.Response || h.RCode != dnsmessage.RCodeSuccess {
		return nil
	}
	q, err := p.Question()
	if err != nil {
		return nil
	}
	if err := p.SkipAllQuestions(); err != nil {
		return nil
	}
	var addrs []netip.Addr
	for {
		ah, err := p.AnswerHeader()
		if err != nil {
			break
		}
		switch ah.Type {
		case dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return nil
			}
			addrs = append(addrs, netip.AddrFrom4(r.A))
		case dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return nil
			}
			addrs = append(addrs, netip.AddrFrom16(r.AAAA).Unmap())
		default:
			if err := p.SkipAnswer(); err != nil {
				return nil
			}
		}
	}
	if len(addrs) == 0 {
		return nil
	}
	return []DNSAnswer{{Name: normalizeName(q.Name.String()), Addrs: addrs}}
}

// tlsHello returns the SNI of a ClientHello starting in data, buffering
// ClientHellos that span several TCP segments (common with post-quantum
// key shares).
func (w *wireNames) tlsHello(k flow4, data []byte) string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if ph := w.pending[k]; ph != nil {
		ph.buf = append(ph.buf, data...)
		if len(ph.buf) < ph.want && len(ph.buf) < 16<<10 {
			return ""
		}
		delete(w.pending, k)
		return sniFromRecord(ph.buf)
	}
	// TLS handshake record (0x16, version 3.x) carrying a ClientHello (1).
	if len(data) < 6 || data[0] != 0x16 || data[1] != 0x03 || data[5] != 0x01 {
		return ""
	}
	want := 5 + int(binary.BigEndian.Uint16(data[3:5]))
	if len(data) >= want {
		return sniFromRecord(data)
	}
	if len(w.pending) >= maxPendingHellos {
		now := time.Now()
		for pk, ph := range w.pending {
			if now.Sub(ph.at) > 5*time.Second {
				delete(w.pending, pk)
			}
		}
		if len(w.pending) >= maxPendingHellos {
			return ""
		}
	}
	w.pending[k] = &partialHello{buf: append([]byte(nil), data...), want: want, at: time.Now()}
	return ""
}

// sniFromRecord parses a TLS record holding a ClientHello and returns its
// server_name. Truncated input simply yields "".
func sniFromRecord(b []byte) string {
	r := reader{b: b}
	r.skip(5) // record header
	r.skip(4) // handshake type + length
	r.skip(2 + 32)
	r.skip(int(r.u8()))  // session id
	r.skip(int(r.u16())) // cipher suites
	r.skip(int(r.u8()))  // compression methods
	end := r.u16()
	ext := reader{b: r.take(int(end))}
	for !ext.bad && len(ext.b) >= 4 {
		typ, n := ext.u16(), int(ext.u16())
		body := reader{b: ext.take(n)}
		if typ != 0 { // server_name
			continue
		}
		body.skip(2) // list length
		if body.u8() != 0 {
			return ""
		}
		name := string(body.take(int(body.u16())))
		if body.bad || name == "" || strings.ContainsAny(name, " /\\") {
			return ""
		}
		name = normalizeName(name)
		if name == "cloudflare-ech.com" { // Encrypted ClientHello: real name hidden
			return ""
		}
		return name
	}
	return ""
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || n > len(r.b) {
		r.bad = true
		return nil
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) skip(n int) { r.take(n) }

func (r *reader) u8() byte {
	if v := r.take(1); v != nil {
		return v[0]
	}
	return 0
}

func (r *reader) u16() uint16 {
	if v := r.take(2); v != nil {
		return binary.BigEndian.Uint16(v)
	}
	return 0
}
