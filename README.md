# NetProbe

A high-performance, real-time network traffic analyzer built with **Modern C++20**, **Npcap**, and **Dear ImGui**.

![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg) ![Standard](https://img.shields.io/badge/C%2B%2B-20-blue.svg) ![License](https://img.shields.io/badge/license-MIT-blue.svg)

## 🚀 Key Features

- **Real-Time Packet Capture**: Captures live traffic using the Npcap driver.
- **Protocol Parsing**: Deep inspection of Ethernet, IPv4, TCP (including TLS SNI extraction), and UDP headers.
- **Interactive Dashboard**: Powered by Dear ImGui & ImPlot for real-time visualization.
- **High Performance**:
  - **Zero-Copy** header inspection where possible.
  - **Multi-threaded Architecture**: Decoupled Capture (Producer) and Rendering (Consumer) threads using a thread-safe packet queue.

## 🛠️ Tech Stack

- **Language**: C++20
- **Packet Capture**: [Npcap SDK](https://npcap.com/)
- **UI Framework**: [Dear ImGui](https://github.com/ocornut/imgui) + [GLFW](https://www.glfw.org/)
- **Plotting**: [ImPlot](https://github.com/epezent/implot)
- **Build System**: CMake

## 📦 Prerequisites

1. **Windows 10/11**
2. **Visual Studio 2022** (with C++ Desktop Development workload)
3. **Npcap Driver**: Install from [npcap.com](https://npcap.com/#download).
4. **Npcap SDK**:
    - Download the SDK ZIP.
    - Extract it to `C:\Npcap-SDK` (or update the path in `CMakeLists.txt`).

## 🔨 Build Instructions

```powershell
# 1. Clone the repository
git clone https://github.com/YehiaGewily/netprobe-cpp.git
cd netprobe-cpp

# 2. Configure the project with CMake
# (Ensure Npcap SDK is at C:/Npcap-SDK)
cmake -B build -S .

# 3. Build the project (Release mode recommended)
cmake --build build --config Release
```

## 🖥️ Usage

1. Navigate to the build output directory (e.g., `build/Release`).
2. **Important**: Run the executable as **Administrator**. Raw packet capture typically requires elevated privileges.

    ```powershell
    ./NetProbe.exe
    ```

3. The dashboard will launch and automatically start capturing on the first available active network adapter.

## 🧩 Architecture

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

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.
