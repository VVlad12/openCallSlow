// Package srum imports the hourly per-app network history that Windows keeps
// in its System Resource Usage Monitor database (about the last 30 days).
package srum

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Velocidex/ordereddict"
	"github.com/opencallslow/opencallslow/internal/store"
	ese "www.velocidex.com/golang/go-ese/parser"
)

const (
	idMapTable   = "SruDbIdMapTable"
	networkTable = "{973F5D5C-1D90-4944-BE8E-24B94231A174}" // Network Data Usage
)

// ImportFile reads a copy of SRUDB.dat and returns its network rows.
func ImportFile(path string) ([]store.SrumRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ctx, err := ese.NewESEContext(f)
	if err != nil {
		return nil, fmt.Errorf("open ESE database: %w", err)
	}
	cat, err := ese.ReadCatalog(ctx)
	if err != nil {
		return nil, fmt.Errorf("read catalog: %w", err)
	}

	apps := make(map[int64]string)
	err = cat.DumpTable(idMapTable, func(row *ordereddict.Dict) error {
		typ := num(row, "IdType")
		if typ == 3 { // user SID
			return nil
		}
		blob, _ := row.GetString("IdBlob")
		if name := appName(decodeBlob(blob)); name != "" {
			apps[num(row, "IdIndex")] = name
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", idMapTable, err)
	}

	var rows []store.SrumRow
	err = cat.DumpTable(networkTable, func(row *ordereddict.Dict) error {
		ts, ok := row.Get("TimeStamp")
		t, isTime := ts.(time.Time)
		if !ok || !isTime || t.IsZero() {
			return nil
		}
		app := apps[num(row, "AppId")]
		if app == "" {
			app = fmt.Sprintf("app %d", num(row, "AppId"))
		}
		rows = append(rows, store.SrumRow{
			Hour:     t.Truncate(time.Hour).Unix(),
			App:      app,
			Iface:    num(row, "InterfaceLuid"),
			BytesIn:  uint64(num(row, "BytesRecvd")),
			BytesOut: uint64(num(row, "BytesSent")),
		})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read network table: %w", err)
	}
	return mergeHours(rows), nil
}

// mergeHours sums rows that collapse onto the same key (SRUM may write the
// same hour more than once, and different users share an app).
func mergeHours(rows []store.SrumRow) []store.SrumRow {
	type key struct {
		hour  int64
		app   string
		iface int64
	}
	idx := make(map[key]int)
	var out []store.SrumRow
	for _, r := range rows {
		k := key{r.Hour, r.App, r.Iface}
		if i, ok := idx[k]; ok {
			out[i].BytesIn += r.BytesIn
			out[i].BytesOut += r.BytesOut
			continue
		}
		idx[k] = len(out)
		out = append(out, r)
	}
	return out
}

func num(row *ordereddict.Dict, name string) int64 {
	v, _ := row.Get(name)
	switch n := v.(type) {
	case int16:
		return int64(n)
	case uint16:
		return int64(n)
	case int32:
		return int64(n)
	case uint32:
		return int64(n)
	case int64:
		return n
	case uint64:
		return int64(n)
	case uint8:
		return int64(n)
	}
	return 0
}

// decodeBlob turns the hex-encoded UTF-16LE IdBlob into a string.
func decodeBlob(h string) string {
	b, err := hex.DecodeString(h)
	if err != nil || len(b) < 2 {
		return ""
	}
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = uint16(b[2*i]) | uint16(b[2*i+1])<<8
	}
	return strings.TrimRight(string(utf16.Decode(u)), "\x00")
}

// appName normalises SRUM app identifiers to match live capture names:
// "\device\harddiskvolume3\...\chrome.exe" → "chrome.exe",
// "!!SystemSettings.exe!2019/12/07:09:08:51!..." → "systemsettings.exe".
func appName(id string) string {
	id = strings.TrimSpace(id)
	if strings.HasPrefix(id, "!!") {
		if parts := strings.Split(id, "!"); len(parts) > 2 {
			id = parts[2]
		}
	}
	if strings.ContainsAny(id, `\/`) {
		id = filepath.Base(strings.ReplaceAll(id, `\`, "/"))
	}
	return strings.ToLower(id)
}
