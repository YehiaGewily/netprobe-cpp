# NetProbe Release Acceptance Checklist

This document defines the formal validation and acceptance protocol for NetProbe releases. Every release candidate must satisfy these criteria before and immediately after publication.

## 1. Release Architecture & Timing

- **Automated Publication**: Pushing a version tag (e.g. `v1.3.1`) to `origin` triggers GitHub Actions (`.github/workflows/ci.yml`), which builds multi-platform artifacts, generates checksums, and publishes the release.
- **Verification Phases**:
  - **Phase 1 (Pre-Tag)**: Gated on a pristine local build, 100% test pass rate, and green CI across all jobs on `main`.
  - **Phase 2 (Post-Publication Acceptance)**: Gated on downloading the public artifacts from GitHub and executing the complete GUI and live-capture test protocol on clean target systems.
- **Post-Release Failure Policy**: Published release tags and assets are immutable. Never move, re-tag, or force-push `v1.3.1`. If a critical defect is identified after publication, immediately mark the release with a prominent advisory warning in the GitHub release notes and ship a subsequent hotfix patch (e.g. `v1.3.2`).

---

## 2. Phase 1: Pre-Tag Verification (Maintainer Checklist)

Before creating or pushing the release tag:

- [ ] **Working Tree Pristine**: `git status` shows no uncommitted changes or untracked files.
- [ ] **Clean Local Rebuild & Test**:
  ```powershell
  cmake -S . -B build-release-verify -G "Visual Studio 17 2022" -A x64 -DBUILD_TESTING=ON
  cmake --build build-release-verify --config Release --parallel 1
  ctest --test-dir build-release-verify -C Release --output-on-failure
  ```
  *Result*: All 95 tests pass (0 failures).
- [ ] **Local Binary & Package Inspection**:
  ```powershell
  # Verify version string
  .\build-release-verify\Release\netprobe-cli.exe --version
  # Generate local CPack package
  cpack --config build-release-verify/CPackConfig.cmake -C Release -G ZIP -B build-release-verify/package
  # Verify package name contains target version (NetProbe-1.3.1-Windows.zip)
  Expand-Archive build-release-verify/package/NetProbe-1.3.1-Windows.zip -DestinationPath build-release-verify/smoke
  .\build-release-verify\smoke\netprobe-cli.exe --version
  ```
- [ ] **Stale References Audit**: Audited repository for leftover version strings, outdated test counts, and obsolete package requirements while preserving historical changelog records.
- [ ] **Main Branch CI Green**: All jobs for the target commit on `main` passed completely:
  - Windows x64 build, test, package, smoke-test
  - Ubuntu x64 build, test, package, smoke-test
  - macOS build, test, package, smoke-test (universal binary & DMG mount)
  - ASan + UBSan (Clang/Ubuntu)
  - Fuzz parser (60s libFuzzer run)
  - clang-tidy (static analysis clean)
- [ ] **Tag Availability**: Verified `git fetch --tags origin` and confirmed `v1.3.1` does not already exist locally or on remote.

---

## 3. Phase 2: Post-Publication Downloaded Artifact Verification

Execute against artifacts downloaded from `https://github.com/YehiaGewily/netprobe-cpp/releases/tag/v1.3.1`:

### 3.1 Artifacts & Checksums Integrity
- [ ] Download all 5 release assets:
  - `NetProbe-1.3.1-Windows.zip`
  - `NetProbe-1.3.1-Linux.zip`
  - `NetProbe-1.3.1-Darwin.zip`
  - `NetProbe-1.3.1-Darwin.dmg`
  - `SHA256SUMS.txt`
- [ ] Verify SHA-256 hashes match `SHA256SUMS.txt` on every file:
  ```bash
  sha256sum -c SHA256SUMS.txt
  ```
- [ ] Package Layout Audit: Ensure extracted packages contain `NetProbe`, `netprobe-cli`, `data/sample.pcap`, `README.md`, `LICENSE`, `THIRD_PARTY_LICENSES.md`, and no stray build artifacts or SDK header leaks (`include/`, `lib/`).
- [ ] Universal Binary Check (macOS):
  ```bash
  lipo -archs NetProbe.app/Contents/MacOS/NetProbe
  lipo -archs netprobe-cli
  ```
  Must report `x86_64 arm64` for both.
- [ ] Static Linking Assertion (Linux):
  ```bash
  for bin in ./NetProbe ./netprobe-cli; do
    readelf -d "$bin" | grep -Eiq '\(NEEDED\).*libpcap' && { echo "FAIL: $bin has dynamic libpcap dependency"; exit 1; }
  done
  echo "PASS: No dynamic libpcap dependency"
  ```

---

## 4. Phase 3: GUI & Live-Capture Acceptance Protocol

Test the extracted prebuilt binaries on target systems:

| Test Case | Description | Expected Outcome |
|---|---|---|
| **TC-01: Offline Sample Replay** | File → Open PCAP (`data/sample.pcap`) | All packets load instantly; protocol hierarchy and flows populate; no crash. |
| **TC-02: Headless CLI Flow Export** | Run `netprobe-cli -r data/sample.pcap -o flows.json` and `-o flows.csv` | Both export files created with valid structure and populated records. |
| **TC-03: GUI Visuals & Theme** | Launch GUI; inspect dark theme styling, embedded window icon, and dashboard layout | Modern dark palette renders correctly; window icon visible in titlebar and taskbar; dashboard cards align properly. |
| **TC-04: Adapter Discovery** | Open Capture menu / interface dropdown | Active network interfaces enumerate with IP addresses and friendly names. |
| **TC-05: Live Capture Start/Stop** | Select active interface and start capture; run background traffic; stop capture | Live packet counter increments in real time; byte rates update; capture stops cleanly without hanging. |
| **TC-06: BPF Capture Filter** | Apply BPF filter `tcp port 443` and capture; then test invalid filter `tcp invalid syntax` | Valid filter captures only matching packets; invalid filter displays helpful syntax error without crashing. |
| **TC-07: Packet Inspection** | Click packet row in Live Packets table | Layered decode tree (Ethernet → IP → Transport → App) displays correct fields; hex/ASCII pane highlights payload. |
| **TC-08: Flow Tracking & RTT** | Generate TCP traffic (e.g. `curl https://example.com`); inspect Flows view | Bi-directional flow collapses into single row; initial TCP RTT calculated and color-coded. |
| **TC-09: PCAP Session Export** | File → Export Captured PCAP to disk; re-open in Wireshark or `tcpdump` | Exported file re-opens cleanly with identical packet count and timestamps. |
| **TC-10: Settings Persistence** | Toggle theme / change queue capacity cap / toggle auto-scroll; restart app | Settings persist across application restarts in user configuration. |
| **TC-11: Sustained Live Capture** | Run continuous live capture under typical workloads for > 5 minutes | Queue drop counters remain stable; memory consumption remains bounded; no leaks. |
| **TC-12: Windows Privilege & SmartScreen** | Test on clean Windows machine with Npcap installed | First run displays SmartScreen prompt; "More info" → "Run anyway" launches cleanly; "Run as Administrator" captures live packets. |
| **TC-13: Linux Privileges (X11 & Wayland)** | Grant capability: `sudo setcap cap_net_raw,cap_net_admin+eip ./NetProbe`; run without `sudo` under X11 and Wayland | App connects to compositor as unprivileged user; live capture succeeds without root GUI execution. |
| **TC-14: macOS Gatekeeper & BPF** | Mount DMG; drag `NetProbe.app` to `/Applications`; launch via Control-click → Open | Gatekeeper prompt bypassed cleanly on first run; live capture opens `/dev/bpf*` when authorized. |

---

## 5. Formal Acceptance Sign-Off Record

Record of post-publication verification results for release **v1.3.1** (published 2026-09-02):

| Target OS & Version | Downloaded Artifact File | SHA-256 Checksum Verified | Verification Date | Tester | Status | Notes |
|---|---|---|---|---|---|---|
| Windows 11 x64 | `NetProbe-1.3.1-Windows.zip` (`69d7fe68...`) | [x] Yes | 2026-09-02 | YehiaGewily | PASS | Downloaded from GitHub release; SHA-256 matched; layout clean; CLI reports 1.3.1; JSON/CSV export on sample.pcap verified; offline GUI & Admin live capture verified. |
| Ubuntu 24.04 LTS (X11) | `NetProbe-1.3.1-Linux.zip` (`75409cc9...`) | [x] Yes | 2026-09-02 | GitHub CI & YehiaGewily | PASS | Statically linked libpcap verified via `readelf -d` in smoke test; no system libpcap-dev dependency; sample PCAP flow export verified. |
| Ubuntu 24.04 LTS (Wayland) | `NetProbe-1.3.1-Linux.zip` (`75409cc9...`) | [x] Yes | 2026-09-02 | GitHub CI & YehiaGewily | PASS | Self-contained static binary verified; capability execution (`setcap cap_net_raw,cap_net_admin+eip`) verified without sudo. |
| macOS 14 / 15 (Universal) | `NetProbe-1.3.1-Darwin.dmg` (`d8670951...`) / `.zip` (`8be66541...`) | [x] Yes | 2026-09-02 | GitHub CI & YehiaGewily | PASS | DMG mount verified; universal binaries (`x86_64` & `arm64`) verified via `lipo`; Info.plist validated via `plutil`; in-situ CLI export verified. |

