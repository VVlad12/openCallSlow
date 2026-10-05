package enrich

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// IPDBURL is the free ip2asn dataset (iptoasn.com, PDDL licence): address
// ranges with their autonomous system number, country and AS name.
const IPDBURL = "https://iptoasn.com/data/ip2asn-combined.tsv.gz"

const IPDBFile = "ip2asn-combined.tsv.gz"

type IPInfo struct {
	ASN     uint32
	Country string
	Org     string
}

type range4 struct {
	start, end uint32
	info       uint32
}

type range6 struct {
	start, end [16]byte
	info       uint32
}

// IPDB answers "who operates this address" from the ip2asn ranges.
type IPDB struct {
	v4    []range4
	v6    []range6
	infos []IPInfo
}

func LoadIPDB(path string) (*IPDB, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	db := &IPDB{}
	index := make(map[IPInfo]uint32)
	sc := bufio.NewScanner(gz)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		cols := strings.Split(sc.Text(), "\t")
		if len(cols) < 5 {
			continue
		}
		asn, _ := strconv.ParseUint(cols[2], 10, 32)
		if asn == 0 {
			continue // "Not routed"
		}
		start, err1 := netip.ParseAddr(cols[0])
		end, err2 := netip.ParseAddr(cols[1])
		if err1 != nil || err2 != nil {
			continue
		}
		info := IPInfo{ASN: uint32(asn), Country: cols[3], Org: cols[4]}
		idx, ok := index[info]
		if !ok {
			idx = uint32(len(db.infos))
			db.infos = append(db.infos, info)
			index[info] = idx
		}
		if start.Is4() {
			db.v4 = append(db.v4, range4{start: v4num(start), end: v4num(end), info: idx})
		} else {
			db.v6 = append(db.v6, range6{start: start.As16(), end: end.As16(), info: idx})
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	sort.Slice(db.v4, func(i, j int) bool { return db.v4[i].start < db.v4[j].start })
	sort.Slice(db.v6, func(i, j int) bool { return bytes.Compare(db.v6[i].start[:], db.v6[j].start[:]) < 0 })
	return db, nil
}

func v4num(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func (db *IPDB) Lookup(a netip.Addr) (IPInfo, bool) {
	if db == nil {
		return IPInfo{}, false
	}
	a = a.Unmap()
	if a.Is4() {
		n := v4num(a)
		i := sort.Search(len(db.v4), func(i int) bool { return db.v4[i].start > n }) - 1
		if i >= 0 && n <= db.v4[i].end {
			return db.infos[db.v4[i].info], true
		}
		return IPInfo{}, false
	}
	b := a.As16()
	i := sort.Search(len(db.v6), func(i int) bool { return bytes.Compare(db.v6[i].start[:], b[:]) > 0 }) - 1
	if i >= 0 && bytes.Compare(b[:], db.v6[i].end[:]) <= 0 {
		return db.infos[db.v6[i].info], true
	}
	return IPInfo{}, false
}

func (db *IPDB) Ranges() int {
	if db == nil {
		return 0
	}
	return len(db.v4) + len(db.v6)
}

// DownloadIPDB fetches the dataset into dir, replacing any older copy only
// once the new file is complete.
func DownloadIPDB(ctx context.Context, dir string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, IPDBURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "openCallSlow (+https://github.com/opencallslow/opencallslow)")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: %s", IPDBURL, resp.Status)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	dst := filepath.Join(dir, IPDBFile)
	tmp, err := os.CreateTemp(dir, IPDBFile+".*.tmp")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := io.Copy(tmp, resp.Body); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if _, err := LoadIPDB(tmp.Name()); err != nil {
		return "", fmt.Errorf("downloaded file is not valid: %w", err)
	}
	return dst, os.Rename(tmp.Name(), dst)
}
