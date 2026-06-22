# NetProbe

A real-time and offline network traffic analyzer built with **Modern C++20**, **Npcap/libpcap**, and **Dear ImGui**.

![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg) ![Standard](https://img.shields.io/badge/C%2B%2B-20-blue.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Download

Download the ZIP for your platform from [GitHub Releases](https://github.com/YehiaGewily/netprobe-cpp/releases). Windows releases require the [Npcap driver](https://npcap.com/#download) for live capture and PCAP support. Linux and macOS releases require their system libpcap runtime.

## Features

- **Live and offline capture**: inspect an active adapter or drag a `.pcap` into the app.
- **Protocol insight**: Ethernet, VLAN, IPv4, TCP, UDP, TLS SNI, DNS A/AAAA/CNAME, and hostname enrichment.
- **Flows view**: sortable per-connection byte totals, one-second rate, duration, service, hostname, Country, and ASN/organization.
- **Filtering and export**: apply live BPF filters such as `tcp port 443`, then save the retained session as a Wireshark-compatible PCAP.
- **Cross-platform backends**: Npcap on Windows and libpcap on Linux/macOS.

| Live packet analysis | Connection flows | Offline PCAP mode |
| --- | --- | --- |
| Protocol and hostname details | Rate, service, GeoIP, and ASN | No administrator rights required |

## Demo and screenshots

Release media is recorded from a real capture session so it stays faithful to the current UI. The capture script and required filenames are documented in [docs/record-demo.md](docs/record-demo.md).

## Tech Stack

- **Language**: C++20
- **Packet Capture**: [Npcap SDK](https://npcap.com/)
- **UI Framework**: [Dear ImGui](https://github.com/ocornut/imgui) + [GLFW](https://www.glfw.org/)
- **Plotting**: [ImPlot](https://github.com/epezent/implot)
- **Build System**: CMake


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

## Usage

1. Run the executable from the extracted release ZIP or build output directory.
2. **Live capture** usually requires elevated privileges. On Windows:

    ```powershell
    Start-Process ".\build\Release\NetProbe.exe" -Verb RunAs
    ```

3. Select a live adapter in the menu bar, or choose **File → Open PCAP…** / drop a PCAP file onto the window.
4. Use **Flows** for per-connection activity, or enter a BPF filter such as `tcp port 443` in the menu bar.

For GeoIP and ASN columns, place `GeoLite2-Country.mmdb` and `GeoLite2-ASN.mmdb` in `data/`. See [data/README.md](data/README.md).

## Architecture

NetProbe uses a classic **Producer-Consumer** pattern to keep the UI responsive while handling high-throughput traffic.

- **Capture Engine (Producer)**:
  - Runs on a dedicated background `std::jthread`.
  - Uses a platform capture backend: Npcap on Windows or libpcap on Linux/macOS.
  - Pushes raw packet data into the `PacketQueue`.

- **GUI Layer (Consumer)**:
  - Runs on the main application thread.
  - Renders the Dear ImGui interface.
  - Dequeues packets from the `PacketQueue` each frame, parses them, and updates the metrics/graphs.

- **PacketQueue**:
  - A thread-safe wrapper around `std::queue`.
  - Uses `std::mutex` and `std::condition_variable` to prevent race conditions and ensure data integrity.

## Contributing


Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License.


