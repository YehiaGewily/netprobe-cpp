# Privacy Policy

This document describes what personal data the NetProbe project collects
and how it handles it. It is intentionally short because the answer is
"very little."

## The NetProbe application

**NetProbe does not phone home.** It does not send telemetry, crash
reports, usage statistics, or any other data to the project maintainer or
any third party. There is no update-check network request.

NetProbe reads network traffic that the user explicitly chooses to
capture: a live adapter, a local `.pcap`/`.pcapng` file, or the bundled
sample capture. All processing happens locally on the user's machine.
Nothing leaves the machine.

**Local files NetProbe reads or writes:**

- Capture files the user opens or creates.
- Flow exports (CSV/JSON) at the user-chosen output path.
- A small settings file remembering window geometry and theme.
- Optional GeoLite2 database files (`.mmdb`) the user places in `data/`
  for GeoIP/ASN enrichment. These are read locally; no lookup service is
  contacted.

**Network activity from NetProbe itself:** none. NetProbe does not
originate outbound connections. It only observes traffic already on the
wire (with the user's consent, and with the operating system's usual
capture-privilege prompts).

## The project's web presence

The project publishes a static landing page at
<https://github.com/YehiaGewily/netprobe-cpp> and via GitHub Pages. These
are served by GitHub. GitHub collects standard server-side access logs
per its own privacy policy; the NetProbe project does not add analytics,
tracking pixels, cookies, or third-party trackers to those pages.

## GitHub interactions

Users who file issues, open pull requests, or leave comments interact
with GitHub, which handles that data per its own privacy policy. The
project itself does not export or aggregate that data.

## Data the maintainer receives directly

If a user emails the maintainer or reports a vulnerability via GitHub's
private security advisory form, the maintainer receives whatever the
user chose to include (usually a reproduction, a capture file, or an
email address for follow-up). That information is used only to respond
to the report and is not shared with third parties.

## Changes

If this policy changes, the change will be committed to this file with
its rationale in the commit message. The repository's Git history is the
authoritative change log.

## Contact

For privacy questions specifically, open a GitHub issue on the
[NetProbe repository](https://github.com/YehiaGewily/netprobe-cpp/issues)
or use the same channels as the [security policy](SECURITY.md).
