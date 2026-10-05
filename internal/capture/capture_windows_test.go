//go:build windows

package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"

	"github.com/0xrawsec/golang-etw/etw"
)

func record(id uint16, payload []byte) *etw.EventRecord {
	er := &etw.EventRecord{}
	er.EventHeader.EventDescriptor.Id = id
	er.UserData = uintptr(unsafe.Pointer(&payload[0]))
	er.UserDataLength = uint16(len(payload))
	return er
}

func TestDecodeNetIPv4(t *testing.T) {
	p := make([]byte, 0, 40)
	p = binary.LittleEndian.AppendUint32(p, 1234) // PID
	p = binary.LittleEndian.AppendUint32(p, 1460) // size
	p = append(p, 142, 250, 1, 1)                 // daddr
	p = append(p, 192, 168, 1, 20)                // saddr
	p = binary.BigEndian.AppendUint16(p, 443)     // dport
	p = binary.BigEndian.AppendUint16(p, 50000)   // sport
	p = append(p, make([]byte, 16)...)            // seqnum, connid…

	r, v6, udp, in, ok := decodeNet(record(11, p))
	if !ok || v6 || udp || !in {
		t.Fatalf("kind: ok=%v v6=%v udp=%v in=%v", ok, v6, udp, in)
	}
	if r.pid != 1234 || r.size != 1460 || r.dport != 443 || r.sport != 50000 ||
		r.daddr != netip.MustParseAddr("142.250.1.1") || r.saddr != netip.MustParseAddr("192.168.1.20") {
		t.Fatalf("got %+v", r)
	}
}

func TestDecodeNetIPv6UDP(t *testing.T) {
	d := netip.MustParseAddr("2a00:1450:400a:800::200e").As16()
	s := netip.MustParseAddr("2001:db8::5").As16()
	p := make([]byte, 0, 64)
	p = binary.LittleEndian.AppendUint32(p, 42)
	p = binary.LittleEndian.AppendUint32(p, 1200)
	p = append(p, d[:]...)
	p = append(p, s[:]...)
	p = binary.BigEndian.AppendUint16(p, 443)
	p = binary.BigEndian.AppendUint16(p, 61000)
	p = append(p, make([]byte, 12)...)

	r, v6, udp, in, ok := decodeNet(record(58, p))
	if !ok || !v6 || !udp || in {
		t.Fatalf("kind: ok=%v v6=%v udp=%v in=%v", ok, v6, udp, in)
	}
	if r.daddr != netip.AddrFrom16(d) || r.dport != 443 || r.size != 1200 {
		t.Fatalf("got %+v", r)
	}
}

func TestDecodeNetRejectsShortPayload(t *testing.T) {
	if _, _, _, _, ok := decodeNet(record(10, make([]byte, 10))); ok {
		t.Fatal("short payload accepted")
	}
	if _, _, _, _, ok := decodeNet(record(12, make([]byte, 40))); ok {
		t.Fatal("non send/recv event accepted")
	}
}

func TestParseQueryResults(t *testing.T) {
	got := parseQueryResults("type:  5 www3.l.google.com;::ffff:142.250.180.4;2a00:1450:400a:802::2004;")
	want := []netip.Addr{netip.MustParseAddr("142.250.180.4"), netip.MustParseAddr("2a00:1450:400a:802::2004")}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %v", got)
	}
}

func TestSeedDNS(t *testing.T) {
	answers := SeedDNS()
	n := 0
	for _, a := range answers {
		n += len(a.Addrs)
	}
	t.Logf("resolver cache: %d names, %d addresses", len(answers), n)
	for i, a := range answers {
		if i >= 5 {
			break
		}
		t.Logf("  %s → %v", a.Name, a.Addrs)
	}
}
