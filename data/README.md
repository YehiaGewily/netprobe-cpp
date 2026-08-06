# GeoLite2 databases

To enable GeoIP and ASN enrichment, download these free GeoLite2 databases from a MaxMind account and place them in NetProbe's **per-user data directory** (not this folder):

| Platform | Location |
| --- | --- |
| Windows | `%LOCALAPPDATA%\NetProbe\` |
| macOS | `~/Library/Application Support/NetProbe/` |
| Linux | `$XDG_DATA_HOME/netprobe/` (typically `~/.local/share/netprobe/`) |

The two files to drop in there:

- `GeoLite2-Country.mmdb`
- `GeoLite2-ASN.mmdb`

You can override the location by setting the `NETPROBE_DATA_DIR` environment variable — useful for portable installs and CI. NetProbe surfaces the exact directory in its GeoIP status message on startup.

The databases are intentionally not committed to this repository: MaxMind's download service requires your own account and license key. NetProbe starts normally without them, and the Flows table shows `-` in the Country/Org columns until the files are present.

**Note:** older NetProbe releases (≤ 1.2.1) read these files from `data/` next to the executable. Starting with 1.3, they must live in the per-user directory instead — the old location writes inside `NetProbe.app` on macOS, which invalidates the app's code signature.
