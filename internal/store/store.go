// Package store persists aggregated traffic in a local SQLite database and
// answers the dashboard's queries.
package store

import (
	"database/sql"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS traffic (
	minute    INTEGER NOT NULL, -- unix time, start of the minute (UTC)
	app       TEXT    NOT NULL,
	site      TEXT    NOT NULL, -- registrable domain, '' when unknown
	service   TEXT    NOT NULL,
	category  TEXT    NOT NULL,
	remote_ip TEXT    NOT NULL, -- only kept when site is unknown
	asn       INTEGER NOT NULL,
	org       TEXT    NOT NULL,
	country   TEXT    NOT NULL,
	proto     TEXT    NOT NULL,
	scope     TEXT    NOT NULL, -- 'internet' or 'lan'
	bytes_in  INTEGER NOT NULL,
	bytes_out INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS traffic_minute ON traffic(minute);

-- Hourly per-app history imported from Windows SRUM.
CREATE TABLE IF NOT EXISTS srum_network (
	hour      INTEGER NOT NULL, -- unix time (UTC)
	app       TEXT    NOT NULL,
	iface     INTEGER NOT NULL, -- interface LUID
	bytes_in  INTEGER NOT NULL,
	bytes_out INTEGER NOT NULL,
	PRIMARY KEY (hour, app, iface)
);
`

type Store struct {
	db   *sql.DB
	path string
}

func Open(path string) (*Store, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(abs) + "?" + url.Values{
		"_pragma": {"busy_timeout(5000)", "journal_mode(WAL)", "synchronous(NORMAL)"},
	}.Encode()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("init schema: %w", err)
	}
	return &Store{db: db, path: abs}, nil
}

func (s *Store) Close() error { return s.db.Close() }
func (s *Store) Path() string { return s.path }

type Row struct {
	Minute   int64
	App      string
	Site     string
	Service  string
	Category string
	RemoteIP string
	ASN      uint32
	Org      string
	Country  string
	Proto    string
	Scope    string
	BytesIn  uint64
	BytesOut uint64
}

func (s *Store) InsertTraffic(rows []Row) error {
	if len(rows) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO traffic
		(minute, app, site, service, category, remote_ip, asn, org, country, proto, scope, bytes_in, bytes_out)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.Minute, r.App, r.Site, r.Service, r.Category, r.RemoteIP, r.ASN,
			r.Org, r.Country, r.Proto, r.Scope, r.BytesIn, r.BytesOut); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type SrumRow struct {
	Hour     int64
	App      string
	Iface    int64
	BytesIn  uint64
	BytesOut uint64
}

// UpsertSrum stores SRUM rows; re-importing the same hours is harmless.
func (s *Store) UpsertSrum(rows []SrumRow) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(`INSERT INTO srum_network (hour, app, iface, bytes_in, bytes_out)
		VALUES (?,?,?,?,?)
		ON CONFLICT (hour, app, iface) DO UPDATE SET bytes_in = excluded.bytes_in, bytes_out = excluded.bytes_out`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, r := range rows {
		if _, err := stmt.Exec(r.Hour, r.App, r.Iface, r.BytesIn, r.BytesOut); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Filter narrows a query to rows matching every non-empty field.
type Filter struct {
	App, Service, Category, Site, Org, Country string
}

func (f Filter) where(from, to int64) (string, []any) {
	conds := []string{"minute >= ?", "minute < ?"}
	args := []any{from, to}
	for col, v := range map[string]string{
		"app": f.App, "service": f.Service, "category": f.Category,
		"site": f.Site, "org": f.Org, "country": f.Country,
	} {
		if v != "" {
			conds = append(conds, col+" = ?")
			args = append(args, v)
		}
	}
	return strings.Join(conds, " AND "), args
}

type Item struct {
	Name string `json:"name"`
	In   uint64 `json:"in"`
	Out  uint64 `json:"out"`
}

type Point struct {
	T   int64  `json:"t"`
	In  uint64 `json:"in"`
	Out uint64 `json:"out"`
}

type Summary struct {
	From       int64             `json:"from"`
	To         int64             `json:"to"`
	Step       int64             `json:"step"`
	Internet   Item              `json:"internet"`
	LAN        Item              `json:"lan"`
	Timeline   []Point           `json:"timeline"`
	Breakdowns map[string][]Item `json:"breakdowns"`
}

// Breakdown dimensions exposed to the dashboard (column names, never user input).
var dimensions = []string{"app", "service", "category", "site", "org", "country"}

// Summary aggregates [from, to) with timeline buckets of step seconds,
// aligned to local time via tzOffset (seconds east of UTC).
func (s *Store) Summary(from, to, step, tzOffset int64, f Filter, top int) (*Summary, error) {
	where, args := f.where(from, to)
	out := &Summary{From: from, To: to, Step: step, Breakdowns: make(map[string][]Item)}

	rows, err := s.db.Query(`SELECT scope, COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0)
		FROM traffic WHERE `+where+` GROUP BY scope`, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var scope string
		var it Item
		if err := rows.Scan(&scope, &it.In, &it.Out); err != nil {
			rows.Close()
			return nil, err
		}
		it.Name = scope
		if scope == "lan" {
			out.LAN = it
		} else {
			out.Internet = it
		}
	}
	rows.Close()

	internet := where + " AND scope = 'internet'"
	rows, err = s.db.Query(`SELECT ((minute + ?) / ?) * ? - ? AS b, SUM(bytes_in), SUM(bytes_out)
		FROM traffic WHERE `+internet+` GROUP BY b ORDER BY b`,
		append([]any{tzOffset, step, step, tzOffset}, args...)...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.T, &p.In, &p.Out); err != nil {
			rows.Close()
			return nil, err
		}
		out.Timeline = append(out.Timeline, p)
	}
	rows.Close()

	for _, dim := range dimensions {
		items, err := s.breakdown(dim, internet, args, top)
		if err != nil {
			return nil, err
		}
		out.Breakdowns[dim] = items
	}
	return out, nil
}

func (s *Store) breakdown(dim, where string, args []any, top int) ([]Item, error) {
	rows, err := s.db.Query(`SELECT `+dim+`, SUM(bytes_in) AS i, SUM(bytes_out) AS o
		FROM traffic WHERE `+where+` AND `+dim+` != ''
		GROUP BY `+dim+` ORDER BY i + o DESC LIMIT ?`, append(args, top)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := []Item{}
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.Name, &it.In, &it.Out); err != nil {
			return nil, err
		}
		items = append(items, it)
	}
	return items, rows.Err()
}

type SrumSummary struct {
	From  int64   `json:"from"`
	To    int64   `json:"to"`
	First int64   `json:"first"` // oldest imported hour, 0 if none
	Last  int64   `json:"last"`
	Total Item    `json:"total"`
	Days  []Point `json:"days"`
	Apps  []Item  `json:"apps"`
}

func (s *Store) Srum(from, to, tzOffset int64, top int) (*SrumSummary, error) {
	out := &SrumSummary{From: from, To: to, Days: []Point{}, Apps: []Item{}}
	if err := s.db.QueryRow(`SELECT COALESCE(MIN(hour),0), COALESCE(MAX(hour),0) FROM srum_network`).
		Scan(&out.First, &out.Last); err != nil {
		return nil, err
	}
	if err := s.db.QueryRow(`SELECT COALESCE(SUM(bytes_in),0), COALESCE(SUM(bytes_out),0)
		FROM srum_network WHERE hour >= ? AND hour < ?`, from, to).Scan(&out.Total.In, &out.Total.Out); err != nil {
		return nil, err
	}
	rows, err := s.db.Query(`SELECT ((hour + ?) / 86400) * 86400 - ? AS d, SUM(bytes_in), SUM(bytes_out)
		FROM srum_network WHERE hour >= ? AND hour < ? GROUP BY d ORDER BY d`, tzOffset, tzOffset, from, to)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var p Point
		if err := rows.Scan(&p.T, &p.In, &p.Out); err != nil {
			rows.Close()
			return nil, err
		}
		out.Days = append(out.Days, p)
	}
	rows.Close()
	rows, err = s.db.Query(`SELECT app, SUM(bytes_in) AS i, SUM(bytes_out) AS o FROM srum_network
		WHERE hour >= ? AND hour < ? GROUP BY app ORDER BY i + o DESC LIMIT ?`, from, to, top)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.Name, &it.In, &it.Out); err != nil {
			return nil, err
		}
		out.Apps = append(out.Apps, it)
	}
	return out, rows.Err()
}
