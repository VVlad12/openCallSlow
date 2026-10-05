package capture

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func ipv4UDP(src, dst string, sport, dport uint16, payload []byte) []byte {
	udp := make([]byte, 8, 8+len(payload))
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	udp = append(udp, payload...)
	return ipv4(src, dst, 17, udp)
}

func ipv4(src, dst string, proto byte, l4 []byte) []byte {
	ip := make([]byte, 20, 20+len(l4))
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(l4)))
	ip[8], ip[9] = 64, proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(ip[12:], s[:])
	copy(ip[16:], d[:])
	ip = append(ip, l4...)
	eth := make([]byte, 14, 14+len(ip))
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	return append(eth, ip...)
}

func tcpSegment(src, dst string, sport, dport uint16, data []byte) []byte {
	tcp := make([]byte, 20, 20+len(data))
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	tcp[12] = 5 << 4
	return ipv4(src, dst, 6, append(tcp, data...))
}

func TestDNSResponseFromFrame(t *testing.T) {
	name := dnsmessage.MustNewName("video-edge-1.ams.abs.hls.ttvnw.net.")
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true, RCode: dnsmessage.RCodeSuccess})
	b.StartQuestions()
	b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET})
	b.StartAnswers()
	b.CNAMEResource(dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET},
		dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("edge.cdn.example.")})
	b.AResource(dnsmessage.ResourceHeader{Name: dnsmessage.MustNewName("edge.cdn.example."), Class: dnsmessage.ClassINET},
		dnsmessage.AResource{A: [4]byte{52, 1, 2, 3}})
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}

	got := newWireNames().frame(ipv4UDP("192.168.1.1", "192.168.1.20", 53, 51000, msg))
	if len(got) != 1 || got[0].Name != "video-edge-1.ams.abs.hls.ttvnw.net" ||
		len(got[0].Addrs) != 1 || got[0].Addrs[0] != netip.MustParseAddr("52.1.2.3") {
		t.Fatalf("got %+v", got)
	}
	// Queries (not responses) are ignored.
	if got := newWireNames().frame(ipv4UDP("192.168.1.20", "192.168.1.1", 51000, 53, msg[:12])); got != nil {
		t.Fatalf("query parsed: %+v", got)
	}
}

func clientHello(sni string, padding int) []byte {
	sn := []byte(sni)
	ext := binary.BigEndian.AppendUint16(nil, 0x0015) // padding extension first
	ext = binary.BigEndian.AppendUint16(ext, uint16(padding))
	ext = append(ext, make([]byte, padding)...)
	ext = binary.BigEndian.AppendUint16(ext, 0) // server_name
	ext = binary.BigEndian.AppendUint16(ext, uint16(5+len(sn)))
	ext = binary.BigEndian.AppendUint16(ext, uint16(3+len(sn)))
	ext = append(ext, 0)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(sn)))
	ext = append(ext, sn...)

	body := []byte{0x03, 0x03}
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id
	body = append(body, 0, 2, 0x13, 0x01)    // one cipher suite
	body = append(body, 1, 0)                // compression
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)

	hs := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	hs = append(hs, body...)
	rec := []byte{0x16, 0x03, 0x01}
	rec = binary.BigEndian.AppendUint16(rec, uint16(len(hs)))
	return append(rec, hs...)
}

func TestSNISingleSegment(t *testing.T) {
	got := newWireNames().frame(tcpSegment("192.168.1.20", "151.101.1.1", 50000, 443, clientHello("www.twitch.tv", 10)))
	if len(got) != 1 || got[0].Name != "www.twitch.tv" || got[0].Addrs[0] != netip.MustParseAddr("151.101.1.1") {
		t.Fatalf("got %+v", got)
	}
}

func TestSNISplitAcrossSegments(t *testing.T) {
	hello := clientHello("rr4---sn-n4v7knll.googlevideo.com", 1600) // > one MSS
	w := newWireNames()
	if got := w.frame(tcpSegment("192.168.1.20", "142.250.1.1", 50001, 443, hello[:1400])); got != nil {
		t.Fatalf("first segment: %+v", got)
	}
	got := w.frame(tcpSegment("192.168.1.20", "142.250.1.1", 50001, 443, hello[1400:]))
	if len(got) != 1 || got[0].Name != "rr4---sn-n4v7knll.googlevideo.com" {
		t.Fatalf("got %+v", got)
	}
	if len(w.pending) != 0 {
		t.Fatal("pending hello not cleared")
	}
}

func TestGarbageIsIgnored(t *testing.T) {
	w := newWireNames()
	for _, b := range [][]byte{nil, {0x45}, make([]byte, 60), tcpSegment("1.1.1.1", "2.2.2.2", 1, 443, []byte{0x16, 0x03, 0x01, 0xff, 0xff, 0x01, 0, 0})} {
		if got := w.frame(b); got != nil {
			t.Fatalf("got %+v from %x", got, b)
		}
	}
}
