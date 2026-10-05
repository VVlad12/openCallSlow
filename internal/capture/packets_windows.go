//go:build windows

package capture

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync/atomic"
	"unsafe"

	"github.com/0xrawsec/golang-etw/etw"
)

// Microsoft-Windows-NDIS-PacketCapture is the built-in packet capture used by
// `netsh trace` and pktmon. We only use it to learn names (see wireNames);
// it runs in its own ETW session so that events dropped under load can only
// cost attribution, never byte counts.
const (
	packetSessionName = "openCallSlow-names"
	ndisCaptureGUID   = "{2ED6006E-4729-4609-B423-3EE7BCD678EF}"
	ndisPacketEvent   = 1001 // MiniportIfIndex u32, LowerIfIndex u32, FragmentSize u32, Fragment[FragmentSize]
)

var ndisCapture = etw.MustParseGUIDFromString(ndisCaptureGUID)

type packetSession struct {
	sess   *etw.RealTimeSession
	cons   *etw.Consumer
	cancel context.CancelFunc
	frames atomic.Uint64
	names  atomic.Uint64
}

func startPackets(h Handler, log *slog.Logger) (*packetSession, error) {
	s := etw.NewRealTimeSession(packetSessionName)
	if err := s.Start(); err != nil {
		return nil, err
	}
	if err := s.EnableProvider(etw.Provider{
		GUID:            ndisCaptureGUID,
		Name:            "Microsoft-Windows-NDIS-PacketCapture",
		EnableLevel:     0xff,
		MatchAnyKeyword: 0xffffffffffffffff,
	}); err != nil {
		s.Stop()
		return nil, fmt.Errorf("enable NDIS-PacketCapture: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ps := &packetSession{sess: s, cancel: cancel}
	wire := newWireNames()
	c := etw.NewRealTimeConsumer(ctx)
	c.FromSessions(s)
	ps.cons = c

	checked := 0 // single ProcessTrace thread: no lock needed
	c.EventRecordCallback = func(er *etw.EventRecord) bool {
		if !er.EventHeader.ProviderId.Equals(ndisCapture) || er.EventHeader.EventDescriptor.Id != ndisPacketEvent {
			return false
		}
		frame, ok := decodeFragment(er)
		if !ok {
			return false
		}
		ps.frames.Add(1)
		for _, a := range wire.frame(frame) {
			ps.names.Add(1)
			h.OnDNS(a)
		}
		if checked < 2 {
			checked++
			return true // let TDH decode it once to verify the layout
		}
		return false
	}
	c.PreparedCallback = func(eh *etw.EventRecordHelper) error {
		frame, _ := decodeFragment(eh.EventRec)
		size, err := eh.GetPropertyUint("FragmentSize")
		if err != nil || int(size) != len(frame) {
			log.Warn("packet capture layout check mismatch — domain names from packets may be missing",
				"tdhFragmentSize", size, "raw", len(frame), "err", err)
		} else {
			log.Debug("packet capture layout check ok", "fragmentSize", size)
		}
		eh.Skip()
		return nil
	}
	c.EventCallback = nil

	if err := c.Start(); err != nil {
		cancel()
		s.Stop()
		return nil, err
	}
	return ps, nil
}

func decodeFragment(er *etw.EventRecord) ([]byte, bool) {
	n := int(er.UserDataLength)
	if er.UserData == 0 || n < 12 {
		return nil, false
	}
	data := unsafe.Slice((*byte)(unsafe.Pointer(er.UserData)), n)
	size := int(binary.LittleEndian.Uint32(data[8:12]))
	if size > n-12 {
		size = n - 12
	}
	return data[12 : 12+size], true
}

func (p *packetSession) Stop() error {
	p.cancel()
	err := p.cons.Stop()
	if serr := p.sess.Stop(); err == nil {
		err = serr
	}
	return err
}
