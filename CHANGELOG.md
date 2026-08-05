# Changelog

All notable changes to NetProbe are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- MIT `LICENSE` shipped in the repo and in every release package.
- `THIRD_PARTY_LICENSES.md` with the license texts of all statically linked
  dependencies, included in every release package.
- Quick-start `README.md` inside the release ZIP, written for binary users.
- `SHA256SUMS.txt` published with every release for download verification.
- `SECURITY.md` with a private vulnerability-reporting channel, plus GitHub
  issue templates.
- Project landing page (GitHub Pages) and promo video.

### Fixed
- Release ZIPs no longer contain Mbed TLS SDK headers and static libraries
  (114 stray files in v1.2.0 packages).
- Release ZIPs can no longer pick up GeoLite2 databases downloaded into the
  packager's `data/` directory.

### Changed
- CI now smoke-tests the extracted release package (layout check plus a real
  CLI run) on all three platforms, and tagged releases are blocked while the
  ASan/UBSan job is failing.

## [1.2.0] — 2026-07-19

### Added
- **`netprobe-cli`**: headless executable running the same capture and
  analysis pipeline for servers, CI, and SSH sessions, with JSON/CSV flow
  export, BPF filters, duration/packet-count limits, and script-friendly exit
  codes.
- **`core::FlowExporter`** with CSV and JSON output shared by GUI and CLI.
- **Per-flow TCP retransmission and out-of-order detection**, surfaced in the
  Flows view.
- **Process ownership in Flows**: flows capture the owning process while the
  socket is live, exported to CSV alongside the GUI column.
- Adversarial malformed-packet test fixtures; clang-tidy static analysis in CI.
- Architecture documentation: five SVG diagrams and a QUIC Initial decryption
  deep-dive.

### Changed
- Core analysis extracted into the **`NetProbeCore` static library**
  (`core::AnalysisSession`), decoupling the engine from the GUI.
- UI performance: cached packet-filter results and flow snapshots, process
  resolution at ingest, DPI content scaling, persisted window geometry.

## [1.1.0] — 2026-07-09

### Added
- Link-layer awareness beyond Ethernet: VLAN/QinQ, Linux cooked captures
  (SLL/SLL2), BSD loopback, and raw-IP, with the original link type preserved
  on export.
- Tunnel decoding (GRE, IP-in-IP, 6in4, VXLAN, GENEVE, MPLS, PPPoE) keying
  flows on the real inner endpoints; encrypted tunnels labelled rather than
  misreported.
- QUIC Initial decryption for v1 and v2, including CRYPTO-frame reassembly
  across multiple Initials.
- TLS ClientHello reassembly across TCP segments for SNI on any port.
- Cleartext HTTP request-line and `Host:` parsing; DNS support extended to
  PTR, SRV, TXT, HTTPS/SVCB, mDNS, and LLMNR.
- Statistics view (protocol hierarchy, top talkers, name-resolution health).

### Changed
- Direction-independent canonical flow keying: both directions of a
  conversation collapse into a single flow.
- Expanded parser unit tests and fuzz coverage.

## [1.0.0] — 2026-06-30

Initial public release: cross-platform (Windows/Linux/macOS) GUI network
analyzer with live capture (Npcap/libpcap) and offline PCAP/PCAPNG replay,
protocol decoding through the packet-detail pane, per-connection Flows view
with initial TCP RTT, GeoIP/ASN enrichment via GeoLite2, BPF capture filters,
display filters, PCAP export, and a bundled `data/sample.pcap` for a
no-privileges first run.

[Unreleased]: https://github.com/YehiaGewily/netprobe-cpp/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/YehiaGewily/netprobe-cpp/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/YehiaGewily/netprobe-cpp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/YehiaGewily/netprobe-cpp/releases/tag/v1.0.0
