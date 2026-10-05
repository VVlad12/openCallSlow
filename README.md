# openCallSlow

**Measure your own digital consumption.** Everyone talks about the footprint of
digital life, but few people have numbers for their own computer. openCallSlow
runs quietly in the background and records how much data each program sends
and receives, and *where it goes* — YouTube vs. Google Search, Teams calls,
cloud sync, updates, ads — then shows it in a local dashboard.

Energy estimation (device power, then the network and data-centre share of
your traffic, as sourced ranges) is the next phase. See [docs/roadmap.md](docs/roadmap.md).

Everything stays on your machine. Nothing is uploaded anywhere.

## What it records

| | Source | Detail |
|---|---|---|
| Live traffic | Windows ETW (`Microsoft-Windows-Kernel-Network`) | per minute · per program · TCP and UDP (incl. QUIC) |
| Destination domain | Windows ETW (`Microsoft-Windows-DNS-Client`) + resolver cache | name each program looked up, grouped into services and categories |
| Network operator & country | [ip2asn](https://iptoasn.com) (public domain) | downloaded automatically, refreshed monthly |
| History | Windows SRUM database | hourly per-app totals, about the last 30 days |

## Quick start (Windows)

Requires [Go](https://go.dev/dl/) 1.23+ to build.

```bash
go build -o bin/opencallslow.exe ./cmd/opencallslow
```

Then, from a terminal opened **as administrator** (live capture needs it):

```bash
bin/opencallslow.exe
```

Open <http://127.0.0.1:7391>. Stop it with Ctrl+C; data is kept in
`%LOCALAPPDATA%\openCallSlow\opencallslow.db` (SQLite).

Other commands:

```
opencallslow serve         dashboard only, over existing data (no admin needed)
opencallslow import-srum   import Windows' hourly history now
opencallslow update-ipdb   refresh the IP → operator/country database
opencallslow help          all flags (-data, -addr, -v)
```

## Limits worth knowing

- **Secure DNS / DNS-over-HTTPS** in a browser hides the domain names from
  Windows; that traffic is then labelled by network operator only (e.g.
  "Google"). Turn off "Use secure DNS" in the browser for full detail.
- **VPN**: traffic can appear twice (inside the tunnel and as the VPN's own traffic).
- **Shared infrastructure**: one IP can serve several domains of the same
  company; we pick the name that program resolved most recently. Video
  traffic (e.g. `googlevideo.com`) is on its own domains, so the big numbers
  are reliable.
- Local-network traffic (NAS, printer, casting) is shown separately and not
  counted as internet use.

## Project layout

```
cmd/opencallslow/   entry point and commands
internal/capture/   OS capture (Windows ETW today; other platforms plug in here)
internal/enrich/    IP → domain/service/category/operator; services.json catalogue
internal/agg/       per-minute aggregation (keeps the hot path tiny)
internal/store/     SQLite schema and dashboard queries
internal/srum/      Windows SRUM history import
internal/web/       local HTTP API
dashboard/          the dashboard (plain HTML/CSS/JS, embedded in the binary)
```

**Contributing a service:** add its domains to
[internal/enrich/services.json](internal/enrich/services.json) — no code needed.

Preview the dashboard with fake data (no admin rights):

```bash
OCS_DEMO_DB=/tmp/ocs-demo/opencallslow.db go test ./internal/store -run TestDemoData
go run ./cmd/opencallslow serve -data /tmp/ocs-demo
```

## Licence

MIT — see [LICENSE](LICENSE).
