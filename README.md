# NetProbe

A high-performance, real-time network traffic analyzer built with **Modern C++20**, **Npcap**, and **Dear ImGui**.

![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg) ![Standard](https://img.shields.io/badge/C%2B%2B-20-blue.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

## Key Features

- **Real-Time Packet Capture**: Captures live traffic using the Npcap driver.
- **Dynamic Device Selection**: Select any active network adapter from the UI at runtime.  
- **Protocol Parsing**: Deep inspection of Ethernet, IPv4, TCP (including TLS SNI extraction), and UDP headers.

## Tech Stack

- **Language**: C++20
- **Packet Capture**: [Npcap SDK](https://npcap.com/)
- **UI Framework**: [Dear ImGui](https://github.com/ocornut/imgui) + [GLFW](https://www.glfw.org/)
- **Plotting**: [ImPlot](https://github.com/epezent/implot)
- **Build System**: CMake

## Prerequisites

1. **Windows 10/11**
2. **Visual Studio 2022** (with C++ Desktop Development workload)
3. **Npcap Driver**: Install from [npcap.com](https://npcap.com/#download).
4. **Npcap SDK**:
    - Download the SDK ZIP.
    - **CRITICAL**: Extract it exactly to `C:\Npcap-SDK` (ensure `Include` and `Lib` are directly inside).

## Build Instructions

```powershell
# 1. Clone the repository
git clone https://github.com/YehiaGewily/netprobe-cpp.git
cd netprobe-cpp

# 2. Build via Script (Recommended)
.\build_project.bat
```

## Usage

1. Navigate to the build output directory (`build/Release`) or run via the script.
2. **Important**: Run the executable as **Administrator**. Raw packet capture typically requires elevated privileges.

    ```powershell
    Start-Process ".\build\Release\NetProbe.exe" -Verb RunAs
    ```

3. **Select Adapter**:
   - The app will launch with no capture running (or auto-select the first device).
   - Go to the **File** menu bar, look for the **"Adapter:"** dropdown.
   - Select your active Wi-Fi or Ethernet interface.
   - You should immediately see traffic spikes in the dashboard.

## Architecture

NetProbe uses a classic **Producer-Consumer** pattern to keep the UI responsive while handling high-throughput traffic.

- **Capture Engine (Producer)**:
  - Runs on a dedicated background `std::jthread`.
  - Interfaces with `wpcap.lib` to poll for network packets.
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


