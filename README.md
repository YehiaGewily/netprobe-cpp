# NetProbe

A real-time and offline network traffic analyzer built with **Modern C++20**, **Npcap/libpcap**, and **Dear ImGui**.

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg) ![Standard](https://img.shields.io/badge/C%2B%2B-20-blue.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Download

Download the ZIP for your platform from [GitHub Releases](https://github.com/YehiaGewily/netprobe-cpp/releases). Windows releases require the [Npcap driver](https://npcap.com/#download) for live capture and PCAP support. Linux and macOS releases require their system libpcap runtime.

## Features

- **Live and offline capture**: inspect an active adapter or drag a `.pcap` / `.pcapng` into the app (classic libpcap and modern PCAPNG both supported).
- **Protocol insight**: Ethernet, VLAN, IPv4/IPv6, TCP, UDP, ARP, ICMP/ICMPv6, DNS A/AAAA/CNAME, TLS SNI, and **QUIC ClientHello SNI** (decrypts QUIC v1 Initial packets to recover the hostname behind UDP/443).
- **Packet detail pane**: click any packet to see a structured Frame → Network → Transport → Application decode plus an `xxd`-style hex dump of the raw bytes.
- **Flows view**: sortable per-connection byte totals, one-second rate, **initial TCP RTT** (from the SYN / SYN-ACK delta, color-coded by latency), duration, service, hostname, Country, and ASN/organization.
- **Process resolution**: the *App* column shows the owning process on Windows (iphlpapi), Linux (`/proc/net/*` + `/proc/<pid>/fd/`), and macOS (`proc_pidfdinfo`).
- **Filtering and export**: apply live BPF filters such as `tcp port 443`, then save the retained session as a Wireshark-compatible PCAP.
- **Cross-platform backends**: Npcap on Windows and libpcap on Linux/macOS.

| Live packet analysis | Connection flows | Offline PCAP mode |
| --- | --- | --- |
| Protocol, hostname, and per-packet hex | Rate, service, GeoIP, and ASN | No administrator rights required |

## Demo and screenshots

![NetProbe live capture](docs/images/demo.gif)

| Live packets | Flows view | Offline PCAP mode |
| --- | --- | --- |
| ![](docs/images/packets.png) | ![](docs/images/flows.png) | ![](docs/images/offline.png) |

Release media is recorded from a real capture session so it stays faithful to the current UI. The capture script and required filenames are documented in [docs/record-demo.md](docs/record-demo.md).

## Tech Stack

- **Language**: C++20
- **Packet Capture**: [Npcap SDK](https://npcap.com/) (Windows) / libpcap (Linux/macOS)
- **UI Framework**: [Dear ImGui](https://github.com/ocornut/imgui) + [GLFW](https://www.glfw.org/) with docking
- **Plotting**: [ImPlot](https://github.com/epezent/implot)
- **Crypto** (QUIC Initial decryption): [Mbed TLS](https://github.com/Mbed-TLS/mbedtls) — HKDF-SHA256, AES-128-ECB, AES-128-GCM
- **GeoIP/ASN**: [libmaxminddb](https://github.com/maxmind/libmaxminddb)
- **File dialogs**: [Native File Dialog Extended](https://github.com/btzy/nativefiledialog-extended)
- **Build System**: CMake (all third-party deps pinned via `FetchContent`)
- **Tests / fuzzing**: GoogleTest + libFuzzer harness on `ProtocolParser` and `DNSParser`


## Prerequisites

NetProbe uses Npcap on Windows and libpcap on Linux/macOS.

- **Windows 10/11**: Visual Studio 2022 with C++ Desktop Development, the [Npcap driver](https://npcap.com/#download), and the Npcap SDK extracted to `C:\Npcap-SDK` (`Include` and `Lib` directly inside).
- **Ubuntu/Debian**: `sudo apt install build-essential cmake libpcap-dev libgl1-mesa-dev libgtk-3-dev pkg-config`
- **macOS**: Xcode Command Line Tools and CMake. libpcap and OpenGL are provided by macOS; Native File Dialog uses Cocoa.

## Build Instructions

```powershell
# 1. Clone the repository
git clone https://github.com/YehiaGewily/netprobe-cpp.git
cd netprobe-cpp

# 2. Build via Script (Recommended)
.\build_project.bat
```

On Linux or macOS:

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --parallel
ctest --test-dir build --output-on-failure
```

To create the same ZIP layout used by Releases:

```bash
cpack --config build/CPackConfig.cmake -C Release -G ZIP -B package
```

### Optional CMake flags

| Flag | Default | What it does |
| --- | --- | --- |
| `-DBUILD_TESTING=ON` | `ON` when top-level | Build the GoogleTest suite (`NetProbeTests`). |
| `-DENABLE_SANITIZERS=ON` | `OFF` | Build with `-fsanitize=address,undefined` (Clang/GCC only). |
| `-DBUILD_FUZZERS=ON` | `OFF` | Build the libFuzzer harness for the protocol parsers. Requires `clang` / `clang-cl`. |

## Usage

1. Run the executable from the extracted release ZIP or build output directory.
2. **No admin? Try the sample first.** The build emits `data/sample.pcap` (mixed ARP / DNS / TLS-SNI traffic with three resolvable hostnames). Open it via **File → Open PCAP…** to exercise the full UI without elevation.
3. **Live capture** usually requires elevated privileges. On Windows:

    ```powershell
    Start-Process ".\build\Release\NetProbe.exe" -Verb RunAs
    ```

4. Select a live adapter in the menu bar, or choose **File → Open PCAP…** / drop a PCAP file onto the window.
5. Use **Flows** for per-connection activity, or enter a BPF filter such as `tcp port 443` in the menu bar.
6. **Click a packet row** in *Live Packets* to populate the *Packet Detail* pane with the layered decode and hex dump.

For GeoIP and ASN columns, place `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` in `data/`. See [data/README.md](data/README.md).

## Architecture

NetProbe uses a classic **Producer-Consumer** pattern to keep the UI responsive while handling high-throughput traffic.

- **Capture backend (`src/capture/`)**: an `ICaptureBackend` interface with Npcap (Windows) and libpcap (Linux/macOS) implementations. Runs on a dedicated `std::jthread` and pushes `PacketData` into the queue.
- **PacketQueue (`src/core/PacketQueue.hpp`)**: thread-safe bounded queue (`std::mutex` + `std::condition_variable`). Drop-oldest on overflow so the UI shows fresh traffic; dropped-packet count is surfaced separately.
- **Protocol stack (`src/core/`)**:
  - `ProtocolParser` — Ethernet → IPv4/IPv6 (with extension headers) → TCP/UDP → service classification.
  - `DNSParser` — A/AAAA/CNAME extraction, feeds `HostnameCache`.
  - `QuicParser` — QUIC v1 Initial decryption (mbedTLS): HKDF-SHA256 from DCID → AES-128-ECB for header protection → AES-128-GCM for the payload → CRYPTO-frame reassembly → TLS ClientHello SNI.
  - `FlowAggregator` — collapses bidirectional flows by canonical key, tracks bytes/rate/duration, and measures the **initial TCP RTT** from the SYN / SYN-ACK timing delta.
  - `GeoIPResolver` — LRU-cached lookups against GeoLite2 MMDBs.
  - `ProcessResolver` — endpoint → PID → executable name. Per-OS branches: Windows iphlpapi, Linux `/proc`, macOS `proc_pidfdinfo`.
- **GUI layer (`src/ui/`)**: Dear ImGui dockspace split across `GuiLayer` (chrome + dockspace), `Dashboard`, `FlowsView`, `PacketView`, and `PacketDetail`. Consumes the queue each frame and updates derived metrics.

## Quality

- **27 unit and integration tests** (GoogleTest) covering protocol parsing, flow aggregation, RTT measurement, queue concurrency, GeoIP lookup, QUIC Initial decryption end-to-end, and both classic-PCAP + PCAPNG fixtures.
- **libFuzzer harness** on `ProtocolParser::parse` and `DNSParser::parseResponse`, with a deterministic seed corpus. CI fuzzes every push for 60 seconds on Ubuntu + Clang and uploads any crash inputs as build artifacts.
- **AddressSanitizer + UndefinedBehaviorSanitizer** CI job runs the full test suite under ASan/UBSan on every push.
- **Three-platform CI matrix** (Windows / Ubuntu / macOS) builds the app, builds and runs the test suite, and packages release ZIPs via CPack on tag pushes. Windows test runs use a 7-Zip-extracted Npcap user-mode DLL so the kernel-driver install is unnecessary in CI.

## Contributing


Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.


