#include <cstdio>
#include <exception>
#include <iostream>
#include <vector>
#include "capture/CaptureEngine.hpp"
#include "core/PacketQueue.hpp"
#include "ui/GuiLayer.hpp"

static int run() {
    std::cout << "Starting NetProbe..." << '\n';

    // 1. Initialize Core Components
    core::PacketQueue queue;
    capture::CaptureEngine engine(queue);

    // 2. Select Network Adapter
    auto devices = engine.getAvailableDevices();
    if (devices.empty()) {
        std::cerr << "No live network devices found. Offline PCAP loading is still available." << '\n';
    }

    // Convert capture::DeviceInfo to ui::GuiLayer::DeviceInfo
    std::vector<ui::GuiLayer::DeviceInfo> uiDevices;
    uiDevices.reserve(devices.size());
    for (const auto& d : devices) {
        uiDevices.push_back({d.name, d.description});
    }

    // 3. Initialize and Run UI
    ui::GuiLayer gui(queue);
    
    // Pass devices to UI
    gui.setDevices(uiDevices);

    if (!gui.init()) {
        std::cerr << "Failed to initialize GUI." << '\n';
        return 1;
    }

    // Handle Device Selection only after the UI is ready to consume packets.
    gui.onDeviceSelected = [&](const std::string& deviceName) {
        std::cout << "Switching to device: " << deviceName << '\n';
        engine.startCapture(deviceName);
    };

    gui.onCaptureStopRequested = [&]() {
        std::cout << "Stopping live capture." << '\n';
        engine.stopCapture();
    };

    gui.onPcapFileSelected = [&](const std::string& path) {
        std::cout << "Loading capture file: " << path << '\n';
        if (!engine.openFile(path)) {
            std::cerr << "Failed to load capture file." << '\n';
        }
    };

    gui.onBpfFilterRequested = [&](const std::string& filter, std::string& error) {
        return engine.setFilter(filter, error);
    };

    gui.onPcapSaveRequested = [&](const std::string& path, std::string& error) {
        return engine.exportSession(path, error);
    };

    // Auto-start on the first device when live capture is available.
    if (!devices.empty()) {
        std::cout << "Auto-selecting device: " << devices[0].name << '\n';
        engine.startCapture(devices[0].name);
        gui.setCaptureActive(true);
    }

    // This blocks until window is closed
    gui.run();

    // 5. Shutdown (RAII handles engine/thread stop)
    std::cout << "NetProbe shutting down." << '\n';
    return 0;
}

int main() {
    // An exception escaping main terminates with no diagnostic at all, which
    // for a windowed application means the window simply vanishes. Report it
    // on a path that cannot itself throw, so the user has something to go on.
    try {
        return run();
    } catch (const std::exception& error) {
        std::fputs("NetProbe: unexpected failure: ", stderr);
        std::fputs(error.what(), stderr);
        std::fputs("\n", stderr);
        return 1;
    } catch (...) {
        std::fputs("NetProbe: unexpected failure\n", stderr);
        return 1;
    }
}
