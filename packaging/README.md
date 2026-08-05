# NetProbe

A real-time and offline network traffic analyzer. This package contains
prebuilt binaries — no compiler or SDK needed.

- `NetProbe` / `NetProbe.exe` — the GUI application
- `netprobe-cli` / `netprobe-cli.exe` — the headless CLI (same engine, no window)
- `data/sample.pcap` — a small capture to try immediately, no admin rights needed
- `LICENSE` (MIT) and `THIRD_PARTY_LICENSES.md`

Project home, documentation, and source: https://github.com/YehiaGewily/netprobe-cpp

## Before you start

- **Windows**: install the [Npcap driver](https://npcap.com/#download) (needed
  for live capture and PCAP support).
- **Linux**: needs the system libpcap runtime (`sudo apt install libpcap0.8`
  on Debian/Ubuntu; usually already present).
- **macOS**: libpcap ships with the OS — nothing to install.

## Quick start

1. Run the `NetProbe` executable.
2. **No admin? Try the sample first.** Open `data/sample.pcap` via
   **File → Open PCAP…** (or drag it onto the window) to explore the full UI
   without elevation.
3. **Live capture** usually requires elevated privileges — "Run as
   administrator" on Windows, `sudo` on Linux/macOS. Then select an adapter in
   the menu bar. A BPF filter such as `tcp port 443` narrows the capture.
4. Use **Flows** for per-connection activity; click a packet row in
   *Live Packets* for the layered decode and hex dump.

## Headless CLI

```bash
# List the adapters available for live capture
netprobe-cli --list-devices

# Replay a capture file and export its flows as JSON
netprobe-cli -r capture.pcap -o flows.json

# Capture live for 60 seconds, filtered, exporting CSV
netprobe-cli -i eth0 -f "tcp port 443" --duration 60 -o flows.csv
```

Run `netprobe-cli --help` for the full flag list.

## Optional: GeoIP and ASN columns

Place `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` (free from MaxMind) in
the `data/` folder next to the executable. `data/README.md` has the details.

## Verify your download

Each release publishes a `SHA256SUMS.txt` asset. Compare your ZIP's SHA-256
hash against it:

```powershell
Get-FileHash NetProbe-*.zip -Algorithm SHA256   # Windows
```

```bash
sha256sum -c SHA256SUMS.txt --ignore-missing    # Linux/macOS (shasum -a 256 on macOS)
```
