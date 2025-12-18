#include <iostream>
#include "capture/CaptureEngine.hpp"
#include "core/PacketQueue.hpp"
#include "core/PacketData.hpp"

// Simple test to verify compilation and linking of CaptureEngine
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
        std::cerr << "Error: No network devices found. Ensure Npcap is installed." << std::endl;
        return 1;
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

    // Handle Device Selection
    gui.onDeviceSelected = [&](std::string deviceName) {
        std::cout << "Switching to device: " << deviceName << std::endl;
        engine.startCapture(deviceName);
    };

    // Auto-start on the first device
    if (!devices.empty()) {
        std::cout << "Auto-selecting device: " << devices[0].description << std::endl;
        engine.startCapture(devices[0].name);
    }

    if (!gui.init()) {
        std::cerr << "Failed to initialize GUI." << std::endl;
        return 1;
    }

    // This blocks until window is closed
    gui.run();

    // 5. Shutdown (RAII handles engine/thread stop)
    std::cout << "NetProbe shutting down." << std::endl;
    return 0;
}
