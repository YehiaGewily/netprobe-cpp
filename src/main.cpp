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

    // Auto-select the first device for now
    // In a real app, we'd pass this list to the UI for selection
    std::string selectedDevice = devices[0].name;
    std::cout << "Selected device: " << devices[0].description << std::endl;

    // 3. Start Capture
    engine.startCapture(selectedDevice);

    // 4. Initialize and Run UI
    ui::GuiLayer gui(queue);
    
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
