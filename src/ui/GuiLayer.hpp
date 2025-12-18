#pragma once

#include "core/PacketQueue.hpp"
#include "core/ParsedPacket.hpp"
#include <vector>
#include <string>
#include <map>
#include <deque>

struct GLFWwindow;

namespace ui {

    // Simple scrolling buffer for ImPlot
    struct ScrollingBuffer {
        int MaxSize;
        int Offset;
        std::vector<float> Data;
        std::vector<float> Time;

        ScrollingBuffer(int max_size = 2000) {
            MaxSize = max_size;
            Offset = 0;
            Data.reserve(MaxSize);
            Time.reserve(MaxSize);
        }

        void AddPoint(float x, float y) {
            if (Data.size() < MaxSize) {
                Data.push_back(y);
                Time.push_back(x);
            } else {
                Data[Offset] = y;
                Time[Offset] = x;
                Offset = (Offset + 1) % MaxSize;
            }
        }

        void Erase() {
            if (Data.size() > 0) {
                Data.clear();
                Time.clear();
                Offset = 0;
            }
        }
    };

    class GuiLayer {
    public:
        struct DeviceInfo {
            std::string name;
            std::string description;
        };

        GuiLayer(core::PacketQueue& queue);
        ~GuiLayer();

        // Initializes GLFW, ImGui, and ImPlot
        bool init();

        // Main Application Loop
        void run();
        
        // Populate device list for UI selection
        void setDevices(const std::vector<DeviceInfo>& devices);
        
        // Callback to start capture on new device
        std::function<void(std::string)> onDeviceSelected;

    private:
        core::PacketQueue& m_queue;
        GLFWwindow* m_window = nullptr;
        
        // Device Management
        std::vector<DeviceInfo> m_devices;
        int m_selectedDeviceIndex = 0;

        // UI State
        std::deque<core::ParsedPacket> m_packetHistory;
        bool m_autoScroll = true;
        
        // Statistics
        std::map<std::string, int> m_appCounts;
        ScrollingBuffer m_bandwidthData;
        double m_lastUpdateTime = 0.0;
        uint64_t m_bytesThisSec = 0;

        void processQueue();
        void renderUI();
        
        // Panels
        void renderMenuBar();
        void renderPacketTable();
        void renderCharts();
    };

} // namespace ui
