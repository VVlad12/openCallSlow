// Package enrich labels a remote address with what it is: domain, service,
// category, network operator and country.
package enrich

import (
	_ "embed"
	"encoding/json"
	"net/netip"
	"strings"
	"sync/atomic"

	"golang.org/x/net/publicsuffix"
)

const (
	ScopeInternet = "internet"
	ScopeLAN      = "lan"

	CategoryOther        = "Other"
	CategoryLAN          = "Local network"
	CategoryUnattributed = "Unattributed"
)

//go:embed services.json
var servicesJSON []byte

type service struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Domains  []string `json:"domains"`
}

type orgRule struct {
	Match string `json:"match"`
	Name  string `json:"name"`
}

type catalogue struct {
	byDomain map[string]*service
	orgs     []orgRule
}

func loadCatalogue() (*catalogue, error) {
	var raw struct {
		Services []*service `json:"services"`
		Orgs     []orgRule  `json:"orgs"`
	}
	if err := json.Unmarshal(servicesJSON, &raw); err != nil {
		return nil, err
	}
	c := &catalogue{byDomain: make(map[string]*service), orgs: raw.Orgs}
	for _, s := range raw.Services {
		for _, d := range s.Domains {
			c.byDomain[strings.ToLower(d)] = s
		}
	}
	return c, nil
}

// match finds the most specific rule for host by stripping labels from the
// left: a.b.youtube.com, b.youtube.com, youtube.com, com.
func (c *catalogue) match(host string) *service {
	for h := host; h != ""; {
		if s, ok := c.byDomain[h]; ok {
			return s
		}
		i := strings.IndexByte(h, '.')
		if i < 0 {
			break
		}
		h = h[i+1:]
	}
	return nil
}

func (c *catalogue) orgName(org string) string {
	u := strings.ToUpper(org)
	for _, r := range c.orgs {
		if strings.HasPrefix(u, r.Match) {
			return r.Name
		}
	}
	return org
}

// Attribution is everything we know about one remote endpoint.
type Attribution struct {
	Site     string // registrable domain, e.g. googlevideo.com
	Service  string // e.g. YouTube
	Category string // e.g. Video streaming
	RemoteIP string // kept only when no domain is known
	ASN      uint32
	Org      string
	Country  string
	Scope    string
}

type Enricher struct {
	DNS  *DNSMap
	ipdb atomic.Pointer[IPDB] // optional; swapped in when downloaded
	cat  *catalogue
}

func New(dns *DNSMap) (*Enricher, error) {
	cat, err := loadCatalogue()
	if err != nil {
		return nil, err
	}
	return &Enricher{DNS: dns, cat: cat}, nil
}

func (e *Enricher) SetIPDB(db *IPDB) { e.ipdb.Store(db) }
func (e *Enricher) IPDB() *IPDB      { return e.ipdb.Load() }

// Skip reports addresses that never leave the machine.
func Skip(a netip.Addr) bool {
	return !a.IsValid() || a.IsLoopback() || a.IsUnspecified()
}

func isLAN(a netip.Addr) bool {
	return a.IsPrivate() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() ||
		a.IsMulticast() || a.IsInterfaceLocalMulticast() || a == netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func (e *Enricher) Attribute(pid uint32, a netip.Addr) Attribution {
	if isLAN(a) {
		return Attribution{Service: CategoryLAN, Category: CategoryLAN, Org: CategoryLAN, Scope: ScopeLAN}
	}
	at := Attribution{Scope: ScopeInternet}
	if info, ok := e.ipdb.Load().Lookup(a); ok {
		at.ASN, at.Country, at.Org = info.ASN, info.Country, e.cat.orgName(info.Org)
	}
	host := e.DNS.Lookup(pid, a)
	if host == "" {
		at.RemoteIP = a.String()
		at.Category = CategoryUnattributed
		at.Service = at.Org
		if at.Service == "" {
			at.Service = "Unknown"
		}
		return at
	}
	if site, err := publicsuffix.EffectiveTLDPlusOne(host); err == nil {
		at.Site = site
	} else {
		at.Site = host
	}
	if s := e.cat.match(host); s != nil {
		at.Service, at.Category = s.Name, s.Category
	} else {
		at.Service, at.Category = at.Site, CategoryOther
	}
	return at
}
