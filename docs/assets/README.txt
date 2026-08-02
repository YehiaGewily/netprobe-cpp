NetProbe landing page — assets
================================

Drop the following files into this folder. The page references them by these
exact names; until they exist, the screens section shows a labelled placeholder
(via an onerror fallback), so the page is not broken in the meantime.

SCREENSHOTS (required — capture from the running app)
-----------------------------------------------------
Recommended size: 1440 x 900 (displayed at 16:10). PNG.

1. live-packets.png
   The Live Packets view — packet list with the Packet Detail pane open on a
   selected row, showing the Frame -> Network -> Transport -> Application decode
   and the xxd-style hex dump. Caption on the page: "Protocol, hostname, and
   per-packet hex".

2. flows.png
   The Flows view — per-connection table with rate, service, hostname, RTT,
   Country, and ASN columns, ideally with the flow detail pane / rate sparkline
   visible. Caption: "Rate, service, GeoIP, and ASN".

3. offline-pcap.png
   Offline mode — a .pcap / .pcapng opened via File -> Open PCAP (or the bundled
   data/sample.pcap). Caption: "No administrator rights required".

OPTIONAL (placeholders currently in use)
----------------------------------------
4. og-image.png   — 1200 x 630 social-share card. Referenced by the og:image and
                    twitter:image meta tags in index.html. Until added, link
                    previews will show no image.

5. favicon.svg    — optional. index.html ships an inline SVG favicon as a data
                    URI (a "probe" descending through network nodes, on a
                    cyan→indigo gradient tile — the same mark as the nav/footer
                    logo), so a real favicon file is NOT required. If you add
                    one, also add <link rel="icon" href="assets/favicon.svg">.

ICONS
-----
The feature-grid and copy-button icons are inline SVG in index.html — no icon
files are needed here.
