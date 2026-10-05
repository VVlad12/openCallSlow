// Package web serves the dashboard and its JSON API on localhost.
package web

import (
	"encoding/json"
	"io/fs"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/opencallslow/opencallslow/dashboard"
	"github.com/opencallslow/opencallslow/internal/store"
)

type Status struct {
	Capturing    bool   `json:"capturing"`
	CaptureError string `json:"captureError,omitempty"`
	Started      int64  `json:"started"`
	Events       uint64 `json:"events"`
	LostEvents   uint64 `json:"lostEvents"`
	DNSAddrs     int    `json:"dnsAddrs"`
	IPDBRanges   int    `json:"ipdbRanges"`
	DB           string `json:"db"`
}

func Handler(st *store.Store, status func() Status, log *slog.Logger) http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(dashboard.Files, ".")
	mux.Handle("GET /", http.FileServerFS(static))

	mux.HandleFunc("GET /api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, status())
	})

	mux.HandleFunc("GET /api/summary", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		from, to, tz := rangeParams(r)
		f := store.Filter{
			App: q.Get("app"), Service: q.Get("service"), Category: q.Get("category"),
			Site: q.Get("site"), Org: q.Get("org"), Country: q.Get("country"),
		}
		sum, err := st.Summary(from, to, stepFor(to-from), tz, f, 25)
		if err != nil {
			log.Error("summary query", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, sum)
	})

	mux.HandleFunc("GET /api/srum", func(w http.ResponseWriter, r *http.Request) {
		from, to, tz := rangeParams(r)
		sum, err := st.Srum(from, to, tz, 25)
		if err != nil {
			log.Error("srum query", "err", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, sum)
	})
	return mux
}

// rangeParams reads from/to (unix seconds) and tz (seconds east of UTC),
// defaulting to the last 24 hours.
func rangeParams(r *http.Request) (from, to, tz int64) {
	q := r.URL.Query()
	now := time.Now().Unix()
	to = parseInt(q.Get("to"), now)
	from = parseInt(q.Get("from"), to-86400)
	tz = parseInt(q.Get("tz"), 0)
	if from > to {
		from, to = to, from
	}
	return
}

func stepFor(span int64) int64 {
	switch {
	case span <= 3*3600:
		return 60
	case span <= 26*3600:
		return 900
	case span <= 8*86400:
		return 3600
	}
	return 86400
}

func parseInt(s string, def int64) int64 {
	if v, err := strconv.ParseInt(s, 10, 64); err == nil {
		return v
	}
	return def
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(v)
}
