//go:build windows

package capture

import (
	"net/netip"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// seedDNS reads the resolver cache through Get-DnsClientCache. The
// documented dnsapi calls cannot read cached answers without querying the
// network again, and this runs only once at startup.
func seedDNS() []DNSAnswer {
	const script = `[Console]::OutputEncoding = [Text.Encoding]::UTF8; ` +
		`Get-DnsClientCache | Where-Object { $_.Type -eq 1 -or $_.Type -eq 28 } | ` +
		`ForEach-Object { $_.Entry + "` + "`t" + `" + $_.Data }`
	cmd := exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	done := make(chan []byte, 1)
	go func() {
		out, _ := cmd.Output()
		done <- out
	}()
	var out []byte
	select {
	case out = <-done:
	case <-time.After(15 * time.Second):
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
		return nil
	}
	return parseCacheDump(string(out))
}

func parseCacheDump(s string) []DNSAnswer {
	byName := make(map[string][]netip.Addr)
	var order []string
	for _, line := range strings.Split(s, "\n") {
		name, data, ok := strings.Cut(strings.TrimSpace(line), "\t")
		if !ok {
			continue
		}
		a, err := netip.ParseAddr(strings.TrimSpace(data))
		if err != nil {
			continue
		}
		name = normalizeName(name)
		if _, seen := byName[name]; !seen {
			order = append(order, name)
		}
		byName[name] = append(byName[name], a.Unmap())
	}
	out := make([]DNSAnswer, 0, len(order))
	for _, n := range order {
		out = append(out, DNSAnswer{Name: n, Addrs: byName[n]})
	}
	return out
}
