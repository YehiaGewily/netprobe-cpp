#pragma once

#include "core/AnalysisSession.hpp"
#include "core/PacketData.hpp"
#include "core/PacketQueue.hpp"
#include "core/ParsedPacket.hpp"
#include "core/FlowAggregator.hpp"
#include "core/GeoIPResolver.hpp"
#include <vector>
#include <string>
#include <map>
#include <deque>
#include <functional>
#include <optional>
#include <unordered_map>

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

        // Reflects whether a live capture is currently running (main.cpp
        // auto-starts the first adapter, so the initial state comes from there).
        void setCaptureActive(bool active) { m_captureActive = active; }

        // Callback to start capture on new device
        std::function<void(std::string)> onDeviceSelected;

        // Callback to stop the running live capture.
        std::function<void()> onCaptureStopRequested;

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
            // Owning process resolved at ingest, while the socket is still in
            // the OS table. Stored so the App column stays stable after the
            // connection closes instead of re-resolving every frame.
            std::string process;
        };
        std::deque<PacketRecord> m_packetHistory;
        // Bumped whenever m_packetHistory changes so the display-filter result
        // cache knows when it is stale.
        uint64_t m_packetHistoryVersion = 0;
        int m_selectedPacketIndex = -1; // index into m_packetHistory, or -1 if none
        bool m_autoScroll = true;
        std::optional<core::FlowKey> m_packetFlowFilter;
        int m_flowSortColumn = 7;
        bool m_flowSortAscending = false;

        // Capture lifecycle. "Paused" freezes the UI-side consumption of the
        // queue: the capture thread keeps running and the bounded queue keeps
        // only the freshest packets, so resuming shows current traffic.
        bool m_captureActive = false;
        bool m_capturePaused = false;

        // Display filter: case-insensitive substring match over addresses,
        // ports, protocol, service, and SNI of already-captured packets.
        // Unlike the BPF filter it never affects what is captured.
        char m_displayFilter[128]{};
        bool m_focusDisplayFilter = false;

        // Cached display-filter results: recomputed only when the filter text,
        // the flow filter, or the packet history changes — not every frame.
        std::vector<size_t> m_filteredPacketIndexes;
        std::string m_filterCacheSignature;
        uint64_t m_filterCacheHistoryVersion = UINT64_MAX;

        // Statistics
        std::map<std::string, int> m_appCounts;
        std::map<std::string, uint64_t> m_protocolCounts;
        std::map<std::string, uint64_t> m_protocolBytes;
        // Capture analysis: parsing, SNI recovery, DNS, flows, and process
        // attribution. The GUI owns only presentation state on top of it.
        core::AnalysisSession m_session;
        // Display-only enrichment, so it stays out of the shared session.
        core::GeoIPResolver m_geoIPResolver;

        bool m_dnsNoticeDismissed = false;
        ScrollingBuffer m_bandwidthData;
        ScrollingBuffer m_tcpBandwidth;
        ScrollingBuffer m_udpBandwidth;
        double m_lastUpdateTime = 0.0;
        uint64_t m_bytesThisSec = 0;
        uint64_t m_tcpBytesThisSec = 0;
        uint64_t m_udpBytesThisSec = 0;
        uint64_t m_totalPackets = 0;
        // Scratch vectors reused when linearizing ring buffers for ImPlot.
        std::vector<float> m_scratchTime;
        std::vector<float> m_scratchData;
        bool m_nfdInitialized = false;
        char m_bpfFilter[256]{};
        std::string m_captureStatus;
        bool m_captureStatusIsError = false;
        double m_captureStatusTime = 0.0;

        // Flow snapshot shared by the Flows and Statistics views, refreshed on
        // a 0.5s cadence instead of copying, geo-resolving, and sorting the
        // whole flow table every frame in each view.
        std::vector<core::Flow> m_flowsCache;
        std::unordered_map<std::string, core::GeoIPInfo> m_flowGeoCache;
        double m_lastFlowsRefresh = -1.0;
        uint64_t m_maxFlowBytes = 0;
        bool m_flowSortDirty = true;

        // Windows DPI: content scale of the monitor the window sits on.
        float m_contentScale = 1.0f;

        // Window geometry persisted across runs (0 width = nothing saved).
        int m_savedWindowX = 0;
        int m_savedWindowY = 0;
        int m_savedWindowW = 0;
        int m_savedWindowH = 0;
        bool m_savedWindowMaximized = false;
        bool m_hasSavedWindowPos = false;

        // Frame pacing: full rate only while live data streams or the user is
        // interacting; otherwise the loop sleeps on the event queue.
        double m_lastInputTime = 0.0;

        // Rate history of the currently selected flow, sampled alongside the
        // bandwidth tick to drive the sparkline in the flow detail pane.
        ScrollingBuffer m_flowRateHistory{240};
        std::optional<core::FlowKey> m_flowRateKey;
        double m_lastFlowSampleTime = 0.0;

        // Persisted preferences (netprobe-settings.ini).
        bool m_darkTheme = true;
        float m_uiScale = 1.0f;

        void processQueue();
        void renderUI();
        void clearCaptureView();
        void openPcapFile(const std::string& path);
        void openPcapDialog();
        void applyTheme();
        void loadFonts();
        void loadSettings();
        void saveSettings() const;
        void handleShortcuts();
        void setPaused(bool paused);
        void setStatus(std::string message, bool isError);
        void refreshFlowsCache();
        void sortFlowsCache();
        void captureWindowGeometry();
        // Fixed pixel sizes authored at 100% scale, adjusted for monitor DPI.
        float scaled(float value) const { return value * m_contentScale; }
        bool exportFlowsCsv(const std::string& path, std::string& error);
        bool packetMatchesDisplayFilter(const core::ParsedPacket& packet,
            const std::string& needleLower) const;
        static void linearizeBuffer(const ScrollingBuffer& buffer,
            std::vector<float>& time, std::vector<float>& data);

        // Panels
        void renderTopBar();
        void renderControlBar();
        void renderEncryptedDnsNotice();
        bool encryptedDnsDominates() const;
        void renderPacketTable();
        void renderPacketDetail();
        void renderCharts();
        void renderEmptyState();
        void renderFlowsTable();
        void renderFlowDetail(const core::Flow& flow, const core::GeoIPInfo& geo);
        void renderStatsView();
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
