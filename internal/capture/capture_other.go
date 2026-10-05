//go:build !windows

package capture

import (
	"errors"
	"log/slog"
)

func start(Handler, *slog.Logger) (Session, error) {
	return nil, errors.New("live capture is not implemented on this platform yet")
}

func seedDNS() []DNSAnswer { return nil }
