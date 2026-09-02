# NetProbe

A real-time and offline network traffic analyzer. This package contains
prebuilt binaries — no compiler or SDK needed.

- `NetProbe` / `NetProbe.exe` / `NetProbe.app` — the GUI application
- `netprobe-cli` / `netprobe-cli.exe` — the headless CLI (same engine, no window)
- `data/sample.pcap` — a small capture to try immediately, no admin rights needed
- `LICENSE` (MIT) and `THIRD_PARTY_LICENSES.md`

On **macOS**, the download is a `.dmg` you mount and open in Finder. Drag
`NetProbe.app` to `Applications` to install it — the bundled sample capture
travels with the app, so the "Open bundled sample" button keeps working
after install. The `netprobe-cli` binary lives at the DMG root next to the
loose docs; copy it wherever you keep your other command-line tools.

Project home, documentation, and source: https://github.com/YehiaGewily/netprobe-cpp

## Before you start

- **Windows**: install the [Npcap driver](https://npcap.com/#download) (needed
  for live capture and PCAP support).
- **Linux**: libpcap is statically compiled into the prebuilt binaries, so no
  distro-specific shared libpcap package or SONAME compatibility symlink is
  needed. Standard desktop runtime dependencies include glibc, GTK3 (used for
  native file dialogs), OpenGL/Mesa, and window-system libraries.
- **macOS**: libpcap ships with the OS — nothing to install.

## Quick start

1. Run the `NetProbe` executable.
2. **No admin? Try the sample first.** Open `data/sample.pcap` via
   **File → Open PCAP…** (or drag it onto the window) to explore the full UI
   without elevation.
3. **Live capture** needs permission to open a raw socket. Then select an
   adapter in the menu bar. A BPF filter such as `tcp port 443` narrows the
   capture.
   - **Windows**: "Run as administrator".
   - **Linux**: prefer granting the binary the raw-capture capability once,
     rather than running the whole GUI as root:

     ```bash
     sudo setcap cap_net_raw,cap_net_admin+eip ./NetProbe
     ```

     Then launch `./NetProbe` normally (no `sudo`). This matters on Wayland
     desktops (GNOME, KDE, Hyprland, Sway): running a GUI app with `sudo`
     fails to open a window because the root user can't connect to your
     user's compositor, so the app appears to crash on launch. `setcap`
     avoids that entirely by keeping the app running as you. (`setcap` needs a
     real on-disk file, so grant it after copying the binary out of any
     read-only mount.)
   - **macOS**: run with `sudo`, or add your user to the `access_bpf` group.
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
the per-user data directory NetProbe looks in on startup:

- **Windows** — `%LOCALAPPDATA%\NetProbe\` (typically `C:\Users\<you>\AppData\Local\NetProbe\`)
- **macOS** — `~/Library/Application Support/NetProbe/`
- **Linux** — `$XDG_DATA_HOME/netprobe/` (typically `~/.local/share/netprobe/`)

Create the directory if it doesn't exist. NetProbe's Flows view shows the
Country and ASN columns once it opens the two files. You can override the
location by setting the `NETPROBE_DATA_DIR` environment variable — useful
for portable installs.

`data/README.md` has the MaxMind download details.

## Verify your download and launch
 
Each release publishes a `SHA256SUMS.txt` asset. Always verify your download's
SHA-256 hash and origin before running:
 
```powershell
Get-FileHash NetProbe-*.zip -Algorithm SHA256   # Windows
```
 
```bash
sha256sum -c SHA256SUMS.txt --ignore-missing    # Linux (or macOS DMG)
```
 
On macOS you can also verify the mounted DMG directly:
 
```bash
shasum -a 256 NetProbe-*-Darwin.dmg
```

### Unsigned Binary First-Run Guidance

NetProbe is an independent open-source project, and releases are currently unsigned
(see `SIGNING.md`). Modern operating systems will present a security warning on first launch:

- **Windows SmartScreen**: If "Windows protected your PC" appears, verify the hash
  matches `SHA256SUMS.txt`, then click **More info** → **Run anyway**. Never disable
  SmartScreen globally in Windows Settings.
- **macOS Gatekeeper**: Right-click (or Control-click) `NetProbe.app` and select
  **Open**, then confirm by clicking **Open** in the dialog. Alternatively, go to
  **System Settings → Privacy & Security** and click **Open Anyway**. Never disable
  Gatekeeper system-wide with `spctl`.
