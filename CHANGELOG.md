# Changelog

All notable changes to NetProbe are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.3.1] - 2026-09-02

### Added
- Automated `readelf` verification in Linux CI package smoke tests asserting that prebuilt binaries carry no dynamic `libpcap` dependencies.
- Release acceptance testing checklist (`docs/RELEASE_CHECKLIST.md`) covering automated pre-tag checks, artifact verification, and live-capture acceptance protocols.

### Changed
- Refreshed GUI visual design with modern dark theme styling, embedded window icon, and redesigned dashboard metrics layout.
- Scoped Linux desktop runtime documentation to clarify that prebuilt binaries require standard system libraries (including glibc, GTK3, OpenGL, and window-system libraries), while `libpcap` is self-contained.
- Updated user documentation to recommend verifying the `SHA256SUMS.txt` hash and origin before safely launching unsigned binaries via scoped SmartScreen ("More info" -> "Run anyway") and Gatekeeper (Control-click -> "Open") steps, rather than disabling system protections globally.
- Synced documented test count to 95 unit and integration tests across README, documentation, and signing policy.

### Fixed
- Statically compile `libpcap 1.10.5` via CMake `FetchContent` on Linux and explicitly set `BUILD_WITH_LIBNL OFF` during pcap configuration, resolving undefined symbol link failures and eliminating distro-specific runtime SONAME mismatches (`libpcap.so.0.8` vs `libpcap.so.1`).
- Removed `libpcap-dev` from all Linux CI runner environments, proving the static build is completely self-contained.

## [1.3.0] - 2026-08-06

### Added
- macOS releases now ship a real `NetProbe.app` bundle inside a `.dmg`,
  with an icon, proper `Info.plist`, and a **universal binary** covering
  both Intel and Apple Silicon in one download. Minimum macOS is 10.15.
- Immutable resources (`data/sample.pcap`) now resolve against the
  executable rather than the current working directory, so the GUI's
  "Open bundled sample" works when launched from Finder, Explorer, or
  any directory other than the install location.
- **Per-user data directory** for user-provided files (GeoLite2 `.mmdb`
  databases): `%LOCALAPPDATA%\NetProbe` on Windows,
  `~/Library/Application Support/NetProbe` on macOS,
  `$XDG_DATA_HOME/netprobe` on Linux. Overridable via `NETPROBE_DATA_DIR`.
- `SIGNING.md` (draft — releases are still unsigned) and `PRIVACY.md`
  documenting how signed builds will work and what data the project
  collects (nothing).

### Changed
- **BREAKING (GeoIP only):** GeoLite2 `.mmdb` files must now live in the
  per-user data directory above, not next to the executable. This
  prevents writing inside a signed `NetProbe.app` bundle (which would
  invalidate its signature) and matches OS conventions for
  user-provided data. See `data/README.md`.
- Landing-page fonts are now self-hosted (`docs/assets/fonts/`); the
  page no longer contacts `fonts.googleapis.com` / `fonts.gstatic.com`.
- CI now builds both a ZIP and a DMG on macOS, mounts the DMG with
  `hdiutil` to smoke-test it in situ, verifies both binaries are
  universal via `lipo`, and lints the plist with `plutil`. Release
  checksums cover both ZIP and DMG.

### Fixed
- Removed a build-time absolute path (`NETPROBE_GEOIP_DATA_DIR`) baked
  into the binary that only ever worked on the developer's own machine.

### Documentation
- Draft `SIGNING.md` includes a prominent status banner and future
  tense throughout so it cannot be mistaken for describing shipped
  signing. Removed `CFBundleDocumentTypes` claim from the macOS
  `Info.plist` (the app has no file-open handler yet).

## [1.2.1] — 2026-08-05

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

[Unreleased]: https://github.com/YehiaGewily/netprobe-cpp/compare/v1.3.1...HEAD
[1.3.1]: https://github.com/YehiaGewily/netprobe-cpp/compare/v1.3.0...v1.3.1
[1.3.0]: https://github.com/YehiaGewily/netprobe-cpp/compare/v1.2.1...v1.3.0
[1.2.1]: https://github.com/YehiaGewily/netprobe-cpp/compare/v1.2.0...v1.2.1
[1.2.0]: https://github.com/YehiaGewily/netprobe-cpp/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/YehiaGewily/netprobe-cpp/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/YehiaGewily/netprobe-cpp/releases/tag/v1.0.0
