#pragma once

#include "core/PacketData.hpp"
#include "core/PacketQueue.hpp"
#include "core/ParsedPacket.hpp"
#include "core/HostnameCache.hpp"
#include "core/FlowAggregator.hpp"
#include "core/GeoIPResolver.hpp"
#include "core/ProcessResolver.hpp"
#include <vector>
#include <string>
#include <map>
#include <deque>
#include <functional>
#include <optional>

struct GLFWwindow;
struct ImFont;

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

        // Callback to load an offline capture file.
        std::function<void(std::string)> onPcapFileSelected;

        // Callbacks for live BPF filtering and exporting the retained raw session.
        std::function<bool(const std::string&, std::string&)> onBpfFilterRequested;
        std::function<bool(const std::string&, std::string&)> onPcapSaveRequested;

    private:
        core::PacketQueue& m_queue;
        GLFWwindow* m_window = nullptr;
        
        // Device Management
        std::vector<DeviceInfo> m_devices;
        int m_selectedDeviceIndex = 0;

        // UI State
        // Each row of the live packet table is a PacketRecord — the raw bytes
        // are kept alongside the parsed view so the Packet Detail panel can
        // render a hex dump of exactly what came off the wire.
        struct PacketRecord {
            core::PacketData raw;
            core::ParsedPacket parsed;
        };
        std::deque<PacketRecord> m_packetHistory;
        int m_selectedPacketIndex = -1; // index into m_packetHistory, or -1 if none
        bool m_autoScroll = true;
        std::optional<core::FlowKey> m_packetFlowFilter;
        int m_flowSortColumn = 7;
        bool m_flowSortAscending = false;
        
        // Statistics
        std::map<std::string, int> m_appCounts;
        core::HostnameCache m_hostnameCache;
        core::FlowAggregator m_flowAggregator;
        core::GeoIPResolver m_geoIPResolver;
        core::ProcessResolver m_processResolver;
        ScrollingBuffer m_bandwidthData;
        double m_lastUpdateTime = 0.0;
        uint64_t m_bytesThisSec = 0;
        uint64_t m_totalPackets = 0;
        std::vector<float> m_linearBandwidthTime;
        std::vector<float> m_linearBandwidthData;
        bool m_nfdInitialized = false;
        char m_bpfFilter[256]{};
        std::string m_captureStatus;
        bool m_captureStatusIsError = false;

        void processQueue();
        void renderUI();
        void clearCaptureView();
        void openPcapFile(const std::string& path);
        void applyTheme();
        void loadFonts();

        // Panels
        void renderTopBar();
        void renderControlBar();
        void renderPacketTable();
        void renderPacketDetail();
        void renderCharts();
        void renderFlowsTable();
        void renderKpiStrip();

        // Cached metrics for header tiles
        float m_currentMbps = 0.0f;
        float m_peakMbps = 0.0f;
        size_t m_activeFlowCount = 0;
        std::string m_topService;
        int m_topServiceCount = 0;

        // Fonts loaded in init().
        ImFont* m_fontDefault = nullptr;
        ImFont* m_fontSmall = nullptr;
        ImFont* m_fontHeadline = nullptr;
        ImFont* m_fontBrand = nullptr;
        ImFont* m_fontMono = nullptr; // monospace, used by the hex dump pane

        bool m_layoutBuilt = false;
    };

} // namespace ui
