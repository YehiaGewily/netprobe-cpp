# Security Policy

NetProbe parses untrusted input by design — packets from the wire and
attacker-supplied PCAP/PCAPNG files. Bugs in that path are security bugs, and
reports are very welcome.

## Reporting a vulnerability

Please report vulnerabilities **privately** via GitHub's security advisory
form: [Report a vulnerability](https://github.com/YehiaGewily/netprobe-cpp/security/advisories/new).
Do not open a public issue for anything you believe is exploitable.

NetProbe is maintained by one person. You will normally get an acknowledgement
within a week; a fix timeline depends on severity, and you'll be kept informed.
Please allow a fix to ship before public disclosure.

## Scope

Most valuable reports, roughly in order:

- Memory-safety issues (crashes, overreads, use-after-free) reachable from a
  crafted capture file or crafted live traffic — the parser chain from link
  layer through tunnels to TLS/QUIC/DNS/HTTP is the primary attack surface.
- Issues in the QUIC Initial decryption path (Mbed TLS usage, HKDF/AES).
- Flow-export output that could inject into downstream consumers (CSV/JSON).

Out of scope: issues requiring a compromised local machine, vulnerabilities in
the Npcap/libpcap drivers themselves (report those upstream), and denial of
service against the GUI from pathological-but-valid traffic volumes.

## Existing hardening

Every push is built with AddressSanitizer and UndefinedBehaviorSanitizer over
the full untrusted-bytes path, the protocol parsers run under a libFuzzer
harness in CI, and the test suite includes adversarial malformed-packet
fixtures. A finding that slips past those layers is exactly the kind of report
this policy is for.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release (1.2.x) | Yes |
| Older releases | No — please reproduce on the latest release |
