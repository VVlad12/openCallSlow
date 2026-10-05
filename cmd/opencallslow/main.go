// Command opencallslow measures your computer's internet use per app and
// per destination, and shows it in a local dashboard.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"time"

	"github.com/opencallslow/opencallslow/internal/agg"
	"github.com/opencallslow/opencallslow/internal/capture"
	"github.com/opencallslow/opencallslow/internal/enrich"
	"github.com/opencallslow/opencallslow/internal/srum"
	"github.com/opencallslow/opencallslow/internal/store"
	"github.com/opencallslow/opencallslow/internal/web"
)

const usage = `openCallSlow — measure your digital consumption

Usage:
  opencallslow [command] [flags]

Commands:
  run           capture traffic and serve the dashboard (default; needs administrator)
  serve         serve the dashboard over existing data, without capturing
  import-srum   import Windows' hourly per-app history (needs administrator)
  update-ipdb   download the IP → network operator / country database
  check         capture for 20 seconds and log what was seen (troubleshooting)

The log is also written to opencallslow.log in the data directory.

Flags:
`

func main() {
	cmd := "run"
	args := os.Args[1:]
	if len(args) > 0 && args[0] != "" && args[0][0] != '-' {
		cmd, args = args[0], args[1:]
	}

	fs := flag.NewFlagSet(cmd, flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir(), "directory for the database and downloaded data")
	addr := fs.String("addr", "127.0.0.1:7391", "dashboard listen address")
	srumFile := fs.String("file", "", "import-srum: read this SRUDB.dat copy instead of the live one")
	verbose := fs.Bool("v", false, "verbose logging")
	elevated := fs.Bool("elevated", false, "internal: set when relaunched through the UAC prompt")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usage)
		fs.PrintDefaults()
	}
	fs.Parse(args)

	level := slog.LevelInfo
	if *verbose || cmd == "check" {
		level = slog.LevelDebug
	}
	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "create data directory:", err)
		os.Exit(1)
	}
	var out io.Writer = os.Stderr
	if f, err := openLog(filepath.Join(*dataDir, "opencallslow.log")); err == nil {
		defer f.Close()
		out = io.MultiWriter(os.Stderr, f)
	}
	log := slog.New(slog.NewTextHandler(out, &slog.HandlerOptions{Level: level}))
	log.Info("openCallSlow starting", "command", cmd, "os", runtime.GOOS, "data", *dataDir, "admin", isElevated())

	if *elevated {
		// Own console window: keep it open so the output can be read.
		defer pause()
	}
	needsAdmin := cmd == "run" || cmd == "check" || cmd == "import-srum"
	if needsAdmin && !isElevated() && !*elevated {
		log.Warn("not running as administrator — asking Windows for permission (UAC prompt)")
		if err := relaunchElevated("-data", *dataDir, "-elevated"); err == nil {
			log.Info("continuing in a new administrator window")
			return
		} else {
			log.Warn("could not get administrator rights; live capture will not work", "err", err)
		}
	}

	var err error
	switch cmd {
	case "run":
		err = run(log, *dataDir, *addr, true)
	case "serve":
		err = run(log, *dataDir, *addr, false)
	case "import-srum":
		err = importSrumCmd(log, *dataDir, *srumFile)
	case "check":
		err = check(log, *dataDir, 20*time.Second)
	case "update-ipdb":
		var path string
		if path, err = enrich.DownloadIPDB(context.Background(), *dataDir); err == nil {
			log.Info("IP database updated", "path", path)
		}
	case "help", "-h", "--help":
		fs.Usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		fs.Usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(log, cmd, err)
	}
}

func pause() {
	fmt.Fprint(os.Stderr, "\nPress Enter to close this window.")
	fmt.Scanln()
}

// openLog appends to the log file, starting afresh once it passes 5 MB.
func openLog(path string) (*os.File, error) {
	flags := os.O_CREATE | os.O_WRONLY | os.O_APPEND
	if fi, err := os.Stat(path); err == nil && fi.Size() > 5<<20 {
		flags |= os.O_TRUNC
	}
	return os.OpenFile(path, flags, 0o644)
}

func fatal(log *slog.Logger, what string, err error) {
	log.Error(what+" failed", "err", err)
	if slices.Contains(os.Args, "-elevated") {
		pause()
	}
	os.Exit(1)
}

func defaultDataDir() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "openCallSlow")
		}
	}
	if d := os.Getenv("XDG_DATA_HOME"); d != "" {
		return filepath.Join(d, "opencallslow")
	}
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "share", "opencallslow")
	}
	return "data"
}

func run(log *slog.Logger, dataDir, addr string, doCapture bool) error {
	st, err := store.Open(filepath.Join(dataDir, "opencallslow.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	log.Info("database", "path", st.Path())

	dns := enrich.NewDNSMap()
	enr, err := enrich.New(dns)
	if err != nil {
		return err
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	var wg sync.WaitGroup
	if doCapture {
		wg.Add(1)
		go func() { defer wg.Done(); keepIPDB(ctx, log, dataDir, enr) }()
	}

	var (
		mu         sync.Mutex
		session    capture.Session
		captureErr error
		started    = time.Now()
	)
	if doCapture {
		for _, d := range capture.SeedDNS() {
			dns.Add(d.PID, d.Name, d.Addrs)
		}
		log.Info("seeded DNS names from the resolver cache", "addresses", dns.Len())

		a := agg.New(enr, st, log)
		session, captureErr = capture.Start(a, log)
		if captureErr != nil {
			log.Error("live capture unavailable — dashboard will only show stored data", "err", captureErr)
		} else {
			log.Info("capturing network traffic")
			stop := make(chan struct{})
			wg.Add(1)
			go func() { defer wg.Done(); a.Run(15*time.Second, stop) }()
			go func() {
				<-ctx.Done()
				if err := session.Stop(); err != nil {
					log.Warn("stop capture", "err", err)
				}
				close(stop)
			}()
			wg.Add(1)
			go func() { defer wg.Done(); keepSrum(ctx, log, dataDir, st) }()
		}
	}

	status := func() web.Status {
		mu.Lock()
		defer mu.Unlock()
		s := web.Status{Started: started.Unix(), DNSAddrs: dns.Len(), IPDBRanges: enr.IPDB().Ranges(), DB: st.Path()}
		if session != nil && captureErr == nil {
			s.Capturing = true
			cs := session.Stats()
			s.Events, s.LostEvents = cs.Events, cs.LostEvents
		} else if captureErr != nil {
			s.CaptureError = captureErr.Error()
		} else {
			s.CaptureError = "capture disabled (serve mode)"
		}
		return s
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", addr, err)
	}
	srv := &http.Server{Handler: web.Handler(st, status, log), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 3*time.Second)
		defer c()
		srv.Shutdown(shutdown)
	}()
	log.Info("dashboard ready", "url", "http://"+ln.Addr().String())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	wg.Wait()
	log.Info("stopped")
	return nil
}

// keepIPDB loads the IP database, downloading it when missing or older
// than 30 days.
func keepIPDB(ctx context.Context, log *slog.Logger, dataDir string, enr *enrich.Enricher) {
	path := filepath.Join(dataDir, enrich.IPDBFile)
	if fi, err := os.Stat(path); err == nil {
		if db, err := enrich.LoadIPDB(path); err == nil {
			enr.SetIPDB(db)
			log.Info("IP database loaded", "ranges", db.Ranges())
		} else {
			log.Warn("IP database unreadable", "err", err)
		}
		if time.Since(fi.ModTime()) < 30*24*time.Hour {
			return
		}
	}
	log.Info("downloading IP database", "url", enrich.IPDBURL)
	if _, err := enrich.DownloadIPDB(ctx, dataDir); err != nil {
		log.Warn("IP database download failed — operators and countries will be missing", "err", err)
		return
	}
	if db, err := enrich.LoadIPDB(path); err == nil {
		enr.SetIPDB(db)
		log.Info("IP database loaded", "ranges", db.Ranges())
	}
}

// keepSrum imports SRUM history now and every 6 hours while running.
func keepSrum(ctx context.Context, log *slog.Logger, dataDir string, st *store.Store) {
	for {
		if n, err := importSrum(dataDir, "", st); err != nil {
			log.Warn("SRUM import failed", "err", err)
		} else {
			log.Info("SRUM history imported", "rows", n)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(6 * time.Hour):
		}
	}
}

func importSrumCmd(log *slog.Logger, dataDir, file string) error {
	st, err := store.Open(filepath.Join(dataDir, "opencallslow.db"))
	if err != nil {
		return err
	}
	defer st.Close()
	n, err := importSrum(dataDir, file, st)
	if err == nil {
		log.Info("SRUM history imported", "rows", n)
	}
	return err
}

func importSrum(dataDir, file string, st *store.Store) (int, error) {
	if file == "" {
		tmp, err := os.MkdirTemp(dataDir, "srum-")
		if err != nil {
			return 0, err
		}
		defer os.RemoveAll(tmp)
		if file, err = srum.SnapshotLive(tmp); err != nil {
			return 0, err
		}
	}
	rows, err := srum.ImportFile(file)
	if err != nil {
		return 0, err
	}
	return len(rows), st.UpsertSrum(rows)
}
