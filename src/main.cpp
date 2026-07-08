#include <iostream>
#include <vector>
#include "capture/CaptureEngine.hpp"
#include "core/PacketQueue.hpp"
#include "ui/GuiLayer.hpp"

int main() {
    std::cout << "Starting NetProbe..." << std::endl;

    // 1. Initialize Core Components
    core::PacketQueue queue;
    capture::CaptureEngine engine(queue);

    // 2. Select Network Adapter
    auto devices = engine.getAvailableDevices();
    if (devices.empty()) {
        std::cerr << "No live network devices found. Offline PCAP loading is still available." << std::endl;
    }

    // Convert capture::DeviceInfo to ui::GuiLayer::DeviceInfo
    std::vector<ui::GuiLayer::DeviceInfo> uiDevices;
    for (const auto& d : devices) {
        uiDevices.push_back({d.name, d.description});
    }

    // 3. Initialize and Run UI
    ui::GuiLayer gui(queue);
    
    // Pass devices to UI
    gui.setDevices(uiDevices);

    if (!gui.init()) {
        std::cerr << "Failed to initialize GUI." << std::endl;
        return 1;
    }

    // Handle Device Selection only after the UI is ready to consume packets.
    gui.onDeviceSelected = [&](std::string deviceName) {
        std::cout << "Switching to device: " << deviceName << std::endl;
        engine.startCapture(deviceName);
    };

    gui.onCaptureStopRequested = [&]() {
        std::cout << "Stopping live capture." << std::endl;
        engine.stopCapture();
    };

    gui.onPcapFileSelected = [&](std::string path) {
        std::cout << "Loading capture file: " << path << std::endl;
        if (!engine.openFile(path)) {
            std::cerr << "Failed to load capture file." << std::endl;
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
        std::cout << "Auto-selecting device: " << devices[0].description << std::endl;
        engine.startCapture(devices[0].name);
        gui.setCaptureActive(true);
    }

    // This blocks until window is closed
    gui.run();

    // 5. Shutdown (RAII handles engine/thread stop)
    std::cout << "NetProbe shutting down." << std::endl;
    return 0;
}
