# Roadmap

## Phase 1 — network (done, needs field testing)
- Live per-app, per-destination traffic via ETW, aggregated per minute in SQLite
- Domain → service → category catalogue, operator and country via ip2asn
- SRUM history import
- Local dashboard

## Next
- **Run as a background service** started with Windows (no terminal window).
- **Network energy, outside the computer.** Convert GB to kWh using published
  intensities, shown as a range and never as a single figure:
  - energy-intensity models (kWh/GB, e.g. Aslan et al. 2018 and later updates),
  - "power models" where most network energy is baseload and only a small part
    scales with traffic (e.g. Malmodin et al.), which give far lower marginal values,
  - data-centre share, then CO₂ using the local grid mix (Switzerland is very low-carbon).
  Each number in the dashboard links to its source and assumptions in `docs/methodology.md`.
- **Device energy.** Estimate wall power from CPU/GPU load, CPU package power
  (RAPL) where readable, GPU power (NVML), screen state and battery discharge;
  later calibrate against a smart plug (Shelly / Tasmota / Home Assistant API).
- **Linux and macOS capture** behind the same `capture` interface
  (eBPF / nettop), keeping everything above it unchanged.
- Domain detection without DNS (TLS SNI / QUIC Initial parsing) for browsers using secure DNS.
- Retention: roll minute rows up to hourly after a few weeks to keep the database small.
