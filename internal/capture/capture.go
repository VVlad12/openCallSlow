// Package capture turns OS-level network telemetry into a stream of
// per-process traffic samples and DNS answers. Each platform provides its
// own implementation of Start; everything above this package is portable.
package capture

import (
	"log/slog"
	"net/netip"
	"strings"
)

type Proto uint8

const (
	TCP Proto = iota + 1
	UDP
)

func (p Proto) String() string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return "?"
}

// Packet is one send or receive observed for a process. Depending on the
// platform it may cover several network packets.
type Packet struct {
	PID        uint32
	Proto      Proto
	Remote     netip.Addr
	RemotePort uint16
	Bytes      uint32
	Inbound    bool
}

// DNSAnswer is a completed name lookup made by a process.
type DNSAnswer struct {
	PID   uint32
	Name  string
	Addrs []netip.Addr
}

// Handler receives capture events. Methods are called from the capture
// thread and must be fast and safe for concurrent use.
type Handler interface {
	OnPacket(Packet)
	OnDNS(DNSAnswer)
}

// Stats reports capture health.
type Stats struct {
	Events     uint64
	LostEvents uint64
	// Packet-based name detection (frames inspected, names learned, dropped).
	PacketFrames, PacketNames, PacketLost uint64
}

// Session is a running capture.
type Session interface {
	Stats() Stats
	Stop() error
}

// Start begins capturing and delivering events to h.
func Start(h Handler, log *slog.Logger) (Session, error) {
	return start(h, log)
}

// SeedDNS returns name→address mappings already known to the OS resolver
// cache, so connections opened before the collector started can still be
// attributed to a domain. It is best effort and may return nothing.
func SeedDNS() []DNSAnswer {
	return seedDNS()
}

func normalizeName(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}
