#include "ui/GuiLayer.hpp"
#include "core/DNSParser.hpp"
#include "core/ProtocolParser.hpp"
#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"
#include "nfd.h"
#include <GLFW/glfw3.h>
#include <iostream>
#include <array>
#include <chrono>
#include <cmath>
#include <filesystem>
#include <format>
#include <algorithm>
#include <tuple>
#include <unordered_map>

namespace ui {
    namespace {
        // Linear-inspired palette: near-black canvas, soft borders, single violet accent.
        constexpr ImVec4 kBgBase      = ImVec4(0.039f, 0.039f, 0.047f, 1.00f); // #0A0A0C
        constexpr ImVec4 kBgSurface   = ImVec4(0.075f, 0.075f, 0.094f, 1.00f); // #131318
        constexpr ImVec4 kBgElevated  = ImVec4(0.102f, 0.102f, 0.125f, 1.00f); // #1A1A20
        constexpr ImVec4 kBgInput     = ImVec4(0.117f, 0.117f, 0.149f, 1.00f); // #1E1E26
        constexpr ImVec4 kBorderSoft  = ImVec4(0.122f, 0.122f, 0.149f, 1.00f); // #1F1F26
        constexpr ImVec4 kBorder      = ImVec4(0.165f, 0.165f, 0.208f, 1.00f); // #2A2A35

        constexpr ImVec4 kText1       = ImVec4(0.925f, 0.925f, 0.933f, 1.00f); // #ECECEE
        constexpr ImVec4 kText2       = ImVec4(0.600f, 0.600f, 0.639f, 1.00f); // #9999A3
        constexpr ImVec4 kText3       = ImVec4(0.361f, 0.361f, 0.408f, 1.00f); // #5C5C68

        constexpr ImVec4 kAccent      = ImVec4(0.369f, 0.416f, 0.824f, 1.00f); // #5E6AD2  Linear violet-blue
        constexpr ImVec4 kAccentSoft  = ImVec4(0.369f, 0.416f, 0.824f, 0.22f);
        constexpr ImVec4 kAccentFaint = ImVec4(0.369f, 0.416f, 0.824f, 0.10f);
        constexpr ImVec4 kSuccess     = ImVec4(0.290f, 0.871f, 0.502f, 1.00f); // #4ADE80
        constexpr ImVec4 kWarning     = ImVec4(0.984f, 0.749f, 0.141f, 1.00f); // #FBBF24
        constexpr ImVec4 kDanger      = ImVec4(0.973f, 0.443f, 0.443f, 1.00f); // #F87171

        // Backwards-compat aliases referenced elsewhere in the file.
        constexpr ImVec4 kMuted       = kText2;
        constexpr ImVec4 kAccentDim   = kAccentSoft;
        constexpr ImVec4 kTileBg      = kBgSurface;
        constexpr ImVec4 kTileBorder  = kBorderSoft;

        int64_t currentUnixTimeMicroseconds() {
            return std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }

        std::string formatBytes(uint64_t bytes) {
            constexpr std::array<const char*, 4> units = {"B", "KB", "MB", "GB"};
            double value = static_cast<double>(bytes);
            size_t unit = 0;
            while (value >= 1024.0 && unit + 1 < units.size()) {
                value /= 1024.0;
                ++unit;
            }
            return unit == 0
                ? std::format("{} {}", bytes, units[unit])
                : std::format("{:.1f} {}", value, units[unit]);
        }

        std::string formatCount(uint64_t value) {
            if (value < 1000) return std::format("{}", value);
            if (value < 1'000'000) return std::format("{:.1f}K", value / 1000.0);
            if (value < 1'000'000'000) return std::format("{:.1f}M", value / 1'000'000.0);
            return std::format("{:.1f}B", value / 1'000'000'000.0);
        }

        std::string formatDuration(int64_t firstSeen, int64_t lastSeen) {
            const int64_t seconds = std::max<int64_t>(0, (lastSeen - firstSeen) / 1'000'000);
            return std::format("{:02}:{:02}:{:02}", seconds / 3600, (seconds / 60) % 60, seconds % 60);
        }

        ImVec4 protocolColor(const std::string& protocol) {
            if (protocol == "TCP")  return ImVec4(0.55f, 0.66f, 0.92f, 1.0f);
            if (protocol == "UDP")  return ImVec4(0.55f, 0.78f, 0.55f, 1.0f);
            if (protocol == "ICMP") return ImVec4(0.84f, 0.69f, 0.43f, 1.0f);
            return kText3;
        }

        // Stable accent color for a service tag based on a small hash.
        // Muted Linear-style palette — each color sits at similar saturation/value
        // so different services read as siblings, not competing accents.
        ImVec4 serviceColor(const std::string& service) {
            if (service.empty()) return kText3;
            constexpr std::array<ImVec4, 6> palette = {
                ImVec4(0.45f, 0.52f, 0.91f, 1.0f), // indigo
                ImVec4(0.50f, 0.78f, 0.69f, 1.0f), // teal
                ImVec4(0.91f, 0.62f, 0.52f, 1.0f), // coral
                ImVec4(0.71f, 0.61f, 0.91f, 1.0f), // lavender
                ImVec4(0.84f, 0.73f, 0.45f, 1.0f), // sand
                ImVec4(0.55f, 0.78f, 0.55f, 1.0f), // moss
            };
            size_t h = 0;
            for (char c : service) h = h * 131u + static_cast<unsigned char>(c);
            return palette[h % palette.size()];
        }

        // Small colored dot inline with text; advances the cursor.
        void drawDot(const ImVec4& color, float radius = 3.5f) {
            const ImVec2 pos = ImGui::GetCursorScreenPos();
            const float yMid = pos.y + ImGui::GetTextLineHeight() * 0.5f;
            ImGui::GetWindowDrawList()->AddCircleFilled(
                ImVec2(pos.x + radius + 2.0f, yMid), radius,
                ImGui::GetColorU32(color));
            ImGui::Dummy(ImVec2(radius * 2.0f + 8.0f, ImGui::GetTextLineHeight()));
        }

        // Pill-shaped colored label drawn via the window draw list.
        void drawTag(const char* text, const ImVec4& color) {
            const ImVec2 textSize = ImGui::CalcTextSize(text);
            const ImVec2 padding(8.0f, 2.0f);
            const ImVec2 pos = ImGui::GetCursorScreenPos();
            const ImVec2 size(textSize.x + padding.x * 2.0f, textSize.y + padding.y * 2.0f);
            ImDrawList* dl = ImGui::GetWindowDrawList();
            const ImU32 bg = ImGui::GetColorU32(ImVec4(color.x, color.y, color.z, 0.18f));
            const ImU32 fg = ImGui::GetColorU32(color);
            dl->AddRectFilled(pos, ImVec2(pos.x + size.x, pos.y + size.y), bg, size.y * 0.5f);
            dl->AddText(ImVec2(pos.x + padding.x, pos.y + padding.y), fg, text);
            ImGui::Dummy(size);
        }
    }

    GuiLayer::GuiLayer(core::PacketQueue& queue) : m_queue(queue) {}

    GuiLayer::~GuiLayer() {
        if (m_window) {
            ImGui_ImplOpenGL3_Shutdown();
            ImGui_ImplGlfw_Shutdown();
            ImPlot::DestroyContext();
            ImGui::DestroyContext();
            glfwDestroyWindow(m_window);
            glfwTerminate();
        }
        if (m_nfdInitialized) {
            NFD_Quit();
        }
    }

    bool GuiLayer::init() {
        if (!glfwInit()) return false;

        const char* glsl_version = "#version 130";
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

        m_window = glfwCreateWindow(1440, 900, "NetProbe  -  Network Analyzer", NULL, NULL);
        if (!m_window) {
            glfwTerminate();
            return false;
        }

        glfwMakeContextCurrent(m_window);
        glfwSwapInterval(1); // Enable vsync
        glfwSetWindowUserPointer(m_window, this);
        glfwSetDropCallback(m_window, [](GLFWwindow* window, int pathCount, const char** paths) {
            auto* gui = static_cast<GuiLayer*>(glfwGetWindowUserPointer(window));
            if (gui && pathCount > 0 && paths[0]) {
                gui->openPcapFile(paths[0]);
            }
        });

        m_nfdInitialized = NFD_Init() == NFD_OKAY;
        if (!m_nfdInitialized) {
            std::cerr << "Native file dialog is unavailable: " << NFD_GetError() << std::endl;
        }

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImPlot::CreateContext();

        ImGuiIO& io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;

        // Use a dedicated ini so a previously-saved imgui.ini with the legacy layout
        // doesn't override the new default dockspace on the first run.
        io.IniFilename = "netprobe-layout.ini";

        loadFonts();
        applyTheme();

        ImGui_ImplGlfw_InitForOpenGL(m_window, true);
        ImGui_ImplOpenGL3_Init(glsl_version);

        return true;
    }

    void GuiLayer::loadFonts() {
        ImGuiIO& io = ImGui::GetIO();
        ImFontConfig cfg;
        cfg.OversampleH = 3;
        cfg.OversampleV = 1;
        cfg.PixelSnapH = false;

        const std::filesystem::path regular  = "C:/Windows/Fonts/segoeui.ttf";
        const std::filesystem::path semibold = "C:/Windows/Fonts/seguisb.ttf";

        if (std::filesystem::exists(regular)) {
            m_fontDefault  = io.Fonts->AddFontFromFileTTF(regular.string().c_str(), 15.0f, &cfg);
            m_fontSmall    = io.Fonts->AddFontFromFileTTF(regular.string().c_str(), 12.0f, &cfg);
            const auto& semiPath = std::filesystem::exists(semibold) ? semibold : regular;
            m_fontHeadline = io.Fonts->AddFontFromFileTTF(semiPath.string().c_str(), 28.0f, &cfg);
            m_fontBrand    = io.Fonts->AddFontFromFileTTF(semiPath.string().c_str(), 16.0f, &cfg);
        } else {
            // Fall back to the bundled bitmap font if Segoe UI is unavailable.
            m_fontDefault  = io.Fonts->AddFontDefault();
            m_fontSmall    = m_fontDefault;
            m_fontHeadline = m_fontDefault;
            m_fontBrand    = m_fontDefault;
        }
    }

    void GuiLayer::applyTheme() {
        ImGuiStyle& style = ImGui::GetStyle();

        style.WindowPadding     = ImVec2(18, 16);
        style.FramePadding      = ImVec2(12, 7);
        style.CellPadding       = ImVec2(10, 8);
        style.ItemSpacing       = ImVec2(10, 10);
        style.ItemInnerSpacing  = ImVec2(8, 6);
        style.IndentSpacing     = 22.0f;
        style.ScrollbarSize     = 10.0f;
        style.GrabMinSize       = 10.0f;

        style.WindowBorderSize  = 1.0f;
        style.ChildBorderSize   = 1.0f;
        style.FrameBorderSize   = 0.0f;
        style.PopupBorderSize   = 1.0f;
        style.TabBorderSize     = 0.0f;
        style.SeparatorTextBorderSize = 1.0f;

        style.WindowRounding    = 10.0f;
        style.ChildRounding     = 8.0f;
        style.FrameRounding     = 7.0f;
        style.PopupRounding     = 8.0f;
        style.GrabRounding      = 7.0f;
        style.TabRounding       = 6.0f;
        style.ScrollbarRounding = 6.0f;

        ImVec4* c = style.Colors;
        c[ImGuiCol_Text]                  = kText1;
        c[ImGuiCol_TextDisabled]          = kText3;
        c[ImGuiCol_WindowBg]              = kBgBase;
        c[ImGuiCol_ChildBg]               = kBgBase;
        c[ImGuiCol_PopupBg]               = kBgElevated;
        c[ImGuiCol_Border]                = kBorderSoft;
        c[ImGuiCol_BorderShadow]          = ImVec4(0, 0, 0, 0);
        c[ImGuiCol_FrameBg]               = kBgInput;
        c[ImGuiCol_FrameBgHovered]        = ImVec4(0.149f, 0.149f, 0.184f, 1.00f);
        c[ImGuiCol_FrameBgActive]         = ImVec4(0.169f, 0.169f, 0.212f, 1.00f);
        c[ImGuiCol_TitleBg]               = kBgBase;
        c[ImGuiCol_TitleBgActive]         = kBgBase;
        c[ImGuiCol_TitleBgCollapsed]      = kBgBase;
        c[ImGuiCol_MenuBarBg]             = kBgBase;
        c[ImGuiCol_ScrollbarBg]           = ImVec4(0, 0, 0, 0);
        c[ImGuiCol_ScrollbarGrab]         = ImVec4(0.196f, 0.196f, 0.243f, 1.00f);
        c[ImGuiCol_ScrollbarGrabHovered]  = ImVec4(0.255f, 0.255f, 0.310f, 1.00f);
        c[ImGuiCol_ScrollbarGrabActive]   = ImVec4(0.310f, 0.310f, 0.376f, 1.00f);
        c[ImGuiCol_CheckMark]             = kAccent;
        c[ImGuiCol_SliderGrab]            = kAccent;
        c[ImGuiCol_SliderGrabActive]      = kAccent;
        c[ImGuiCol_Button]                = kBgInput;
        c[ImGuiCol_ButtonHovered]         = ImVec4(0.169f, 0.169f, 0.212f, 1.00f);
        c[ImGuiCol_ButtonActive]          = ImVec4(0.196f, 0.196f, 0.243f, 1.00f);
        c[ImGuiCol_Header]                = kAccentFaint;
        c[ImGuiCol_HeaderHovered]         = kAccentSoft;
        c[ImGuiCol_HeaderActive]          = kAccentSoft;
        c[ImGuiCol_Separator]             = kBorderSoft;
        c[ImGuiCol_SeparatorHovered]      = kBorder;
        c[ImGuiCol_SeparatorActive]       = kAccent;
        c[ImGuiCol_ResizeGrip]            = ImVec4(0, 0, 0, 0);
        c[ImGuiCol_ResizeGripHovered]     = kAccentSoft;
        c[ImGuiCol_ResizeGripActive]      = kAccent;
        c[ImGuiCol_Tab]                   = kBgBase;
        c[ImGuiCol_TabHovered]            = kBgElevated;
        c[ImGuiCol_TabActive]             = kBgSurface;
        c[ImGuiCol_TabUnfocused]          = kBgBase;
        c[ImGuiCol_TabUnfocusedActive]    = kBgSurface;
        c[ImGuiCol_DockingPreview]        = kAccentSoft;
        c[ImGuiCol_DockingEmptyBg]        = kBgBase;
        c[ImGuiCol_PlotLines]             = kAccent;
        c[ImGuiCol_PlotLinesHovered]      = kAccent;
        c[ImGuiCol_PlotHistogram]         = kAccent;
        c[ImGuiCol_PlotHistogramHovered]  = kAccent;
        c[ImGuiCol_TableHeaderBg]         = kBgBase;
        c[ImGuiCol_TableBorderStrong]     = kBorderSoft;
        c[ImGuiCol_TableBorderLight]      = kBorderSoft;
        c[ImGuiCol_TableRowBg]            = ImVec4(0, 0, 0, 0);
        c[ImGuiCol_TableRowBgAlt]         = ImVec4(1, 1, 1, 0.015f);
        c[ImGuiCol_TextSelectedBg]        = kAccentSoft;
        c[ImGuiCol_NavHighlight]          = kAccent;

        // ImPlot — minimal, removes most chrome.
        ImPlotStyle& ps = ImPlot::GetStyle();
        ps.PlotPadding   = ImVec2(8, 8);
        ps.LabelPadding  = ImVec2(4, 4);
        ps.LegendPadding = ImVec2(8, 6);
        ps.PlotBorderSize = 0.0f;
        ps.MajorTickLen  = ImVec2(0, 0);
        ps.MinorTickLen  = ImVec2(0, 0);
        ps.MajorTickSize = ImVec2(0, 0);
        ps.MinorTickSize = ImVec2(0, 0);
        ImVec4* pc = ps.Colors;
        pc[ImPlotCol_FrameBg]      = ImVec4(0, 0, 0, 0);
        pc[ImPlotCol_PlotBg]       = ImVec4(0, 0, 0, 0);
        pc[ImPlotCol_PlotBorder]   = ImVec4(0, 0, 0, 0);
        pc[ImPlotCol_AxisBg]       = ImVec4(0, 0, 0, 0);
        pc[ImPlotCol_AxisGrid]     = ImVec4(0.165f, 0.165f, 0.208f, 0.60f);
        pc[ImPlotCol_AxisText]     = kText3;
        pc[ImPlotCol_TitleText]    = kText1;
        pc[ImPlotCol_LegendBg]     = kBgElevated;
        pc[ImPlotCol_LegendBorder] = kBorderSoft;
        pc[ImPlotCol_LegendText]   = kText1;
    }

    void GuiLayer::run() {
        while (!glfwWindowShouldClose(m_window)) {
            glfwPollEvents();
            processQueue();

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();

            renderUI();

            ImGui::Render();
            int display_w, display_h;
            glfwGetFramebufferSize(m_window, &display_w, &display_h);
            glViewport(0, 0, display_w, display_h);
            glClearColor(0.04f, 0.05f, 0.07f, 1.00f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

            glfwSwapBuffers(m_window);
        }
    }

    void GuiLayer::processQueue() {
        // Process up to 1000 packets per frame to maintain responsiveness
        constexpr size_t maxPacketHistory = 10'000;
        int count = 0;
        double currentTime = glfwGetTime();

        while (count < 1000) {
            auto packetOpt = m_queue.try_pop();
            if (!packetOpt) break;

            auto parsed = core::ProtocolParser::parse(*packetOpt);
            if (const auto dnsResponse = core::DNSParser::parseResponse(*packetOpt)) {
                for (const auto& answer : dnsResponse->answers) {
                    if (answer.type == core::DNSRecordType::A || answer.type == core::DNSRecordType::AAAA) {
                        const std::string& hostname = dnsResponse->queryName.empty()
                            ? answer.name
                            : dnsResponse->queryName;
                        m_hostnameCache.store(answer.value, hostname);
                        m_flowAggregator.setHostnameForAddress(answer.value, hostname);
                    }
                }
            }

            std::string hostname;
            if (!parsed.sni.empty()) {
                hostname = parsed.sni;
            } else if (const auto destinationHostname = m_hostnameCache.lookup(parsed.dstIP)) {
                hostname = *destinationHostname;
            } else if (const auto sourceHostname = m_hostnameCache.lookup(parsed.srcIP)) {
                hostname = *sourceHostname;
            }
            m_flowAggregator.update(parsed, hostname);
            
            // Keep the visual history bounded while retaining all-time counters separately.
            if (m_packetHistory.size() >= maxPacketHistory) m_packetHistory.pop_front();
            m_packetHistory.push_back(parsed);

            // Update Statistics
            ++m_totalPackets;
            m_bytesThisSec += parsed.length;
            if (!parsed.service.empty()) {
                m_appCounts[parsed.service]++;
            }

            count++;
        }

        // Update Bandwidth Chart (Every 0.5s)
        if (currentTime - m_lastUpdateTime >= 0.5) {
            float mbps = (float)m_bytesThisSec / (1024.0f * 1024.0f) / 0.5f; // MB/s
            m_bandwidthData.AddPoint((float)currentTime, mbps);
            m_currentMbps = mbps;
            if (mbps > m_peakMbps) m_peakMbps = mbps;
            m_bytesThisSec = 0;
            m_lastUpdateTime = currentTime;
        }

        // Refresh KPI cache (cheap derived values).
        m_topService.clear();
        m_topServiceCount = 0;
        for (const auto& [name, c] : m_appCounts) {
            if (c > m_topServiceCount) { m_topService = name; m_topServiceCount = c; }
        }
    }

    void GuiLayer::renderUI() {
        // Host window that owns the menu bar, control bar, and dockspace.
        const ImGuiViewport* viewport = ImGui::GetMainViewport();
        ImGui::SetNextWindowPos(viewport->WorkPos);
        ImGui::SetNextWindowSize(viewport->WorkSize);
        ImGui::SetNextWindowViewport(viewport->ID);

        const ImGuiWindowFlags hostFlags =
            ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoCollapse |
            ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
            ImGuiWindowFlags_NoBringToFrontOnFocus | ImGuiWindowFlags_NoNavFocus |
            ImGuiWindowFlags_NoDocking | ImGuiWindowFlags_MenuBar;

        ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
        ImGui::Begin("##NetProbeHost", nullptr, hostFlags);
        ImGui::PopStyleVar(3);

        renderTopBar();
        renderControlBar();

        const ImGuiID dockspaceId = ImGui::GetID("NetProbeDockspace");
        if (!m_layoutBuilt) {
            m_layoutBuilt = true;
            ImGuiDockNode* root = ImGui::DockBuilderGetNode(dockspaceId);
            const bool needsLayout = !root || root->IsLeafNode();
            if (needsLayout) {
                ImGui::DockBuilderRemoveNode(dockspaceId);
                ImGui::DockBuilderAddNode(dockspaceId, ImGuiDockNodeFlags_DockSpace);
                ImGui::DockBuilderSetNodeSize(dockspaceId, ImGui::GetContentRegionAvail());

                ImGuiID topId, bottomId;
                ImGui::DockBuilderSplitNode(dockspaceId, ImGuiDir_Up, 0.50f, &topId, &bottomId);

                ImGuiID flowsId, packetsId;
                ImGui::DockBuilderSplitNode(bottomId, ImGuiDir_Left, 0.55f, &flowsId, &packetsId);

                ImGui::DockBuilderDockWindow("Dashboard", topId);
                ImGui::DockBuilderDockWindow("Flows", flowsId);
                ImGui::DockBuilderDockWindow("Live Packets", packetsId);
                ImGui::DockBuilderFinish(dockspaceId);
            }
        }
        ImGui::DockSpace(dockspaceId, ImVec2(0, 0), ImGuiDockNodeFlags_None);

        ImGui::End();

        renderCharts();
        renderFlowsTable();
        renderPacketTable();
    }

    void GuiLayer::setDevices(const std::vector<DeviceInfo>& devices) {
        m_devices = devices;
    }

    void GuiLayer::clearCaptureView() {
        m_packetHistory.clear();
        m_appCounts.clear();
        m_hostnameCache.clear();
        m_flowAggregator.clear();
        m_packetFlowFilter.reset();
        m_bandwidthData.Erase();
        m_bytesThisSec = 0;
        m_totalPackets = 0;
        m_lastUpdateTime = glfwGetTime();
    }

    void GuiLayer::openPcapFile(const std::string& path) {
        if (path.empty()) return;
        clearCaptureView();
        if (onPcapFileSelected) {
            onPcapFileSelected(path);
        }
    }

    void GuiLayer::renderTopBar() {
        if (!ImGui::BeginMenuBar()) return;

        // Brand
        if (m_fontBrand) ImGui::PushFont(m_fontBrand);
        ImGui::TextColored(kText1, "NetProbe");
        if (m_fontBrand) ImGui::PopFont();

        // LIVE / IDLE indicator with a pulsing dot.
        ImGui::SameLine(0.0f, 14.0f);
        {
            const bool live = m_currentMbps > 0.0001f;
            const float pulse = live
                ? 0.55f + 0.45f * (0.5f + 0.5f * std::sin(static_cast<float>(glfwGetTime()) * 3.0f))
                : 0.55f;
            const ImVec4 dotColor = live
                ? ImVec4(kSuccess.x, kSuccess.y, kSuccess.z, pulse)
                : ImVec4(kText3.x, kText3.y, kText3.z, 1.0f);
            const float r = 4.0f;
            const ImVec2 cursor = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddCircleFilled(
                ImVec2(cursor.x + r, cursor.y + ImGui::GetTextLineHeight() * 0.5f),
                r, ImGui::GetColorU32(dotColor));
            ImGui::Dummy(ImVec2(r * 2.0f + 6.0f, ImGui::GetTextLineHeight()));
            ImGui::SameLine();
            ImGui::TextColored(live ? kText2 : kText3, "%s", live ? "Live" : "Idle");
        }

        ImGui::SameLine(0.0f, 18.0f);
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open PCAP...", "Ctrl+O", false, m_nfdInitialized)) {
                const nfdu8filteritem_t filters[] = {
                    {"Packet captures", "pcap,pcapng,cap"},
                };
                nfdu8char_t* selectedPath = nullptr;
                const nfdresult_t result = NFD_OpenDialogU8(&selectedPath, filters, 1, nullptr);
                if (result == NFD_OKAY) {
                    openPcapFile(selectedPath);
                    NFD_FreePathU8(selectedPath);
                } else if (result == NFD_ERROR) {
                    std::cerr << "Unable to open file dialog: " << NFD_GetError() << std::endl;
                }
            }
            if (ImGui::MenuItem("Save PCAP...", "Ctrl+S", false, m_nfdInitialized)) {
                const nfdu8filteritem_t filters[] = {
                    {"Packet captures", "pcap"},
                };
                nfdu8char_t* selectedPath = nullptr;
                const nfdresult_t result = NFD_SaveDialogU8(
                    &selectedPath, filters, 1, nullptr, "netprobe-session.pcap");
                if (result == NFD_OKAY) {
                    std::string error;
                    if (onPcapSaveRequested && onPcapSaveRequested(selectedPath, error)) {
                        m_captureStatus = "PCAP session saved.";
                        m_captureStatusIsError = false;
                    } else {
                        m_captureStatus = error.empty() ? "Unable to save the PCAP session." : error;
                        m_captureStatusIsError = true;
                    }
                    NFD_FreePathU8(selectedPath);
                } else if (result == NFD_ERROR) {
                    m_captureStatus = NFD_GetError() ? NFD_GetError() : "Unable to open the save dialog.";
                    m_captureStatusIsError = true;
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) glfwSetWindowShouldClose(m_window, true);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            if (ImGui::MenuItem("Reset layout")) {
                m_layoutBuilt = false;
            }
            ImGui::EndMenu();
        }

        ImGui::EndMenuBar();
    }

    void GuiLayer::renderControlBar() {
        ImGui::PushStyleColor(ImGuiCol_ChildBg, kBgBase);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 10));
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 0.0f);
        const float barHeight = ImGui::GetFrameHeightWithSpacing() + 6.0f;

        ImGui::BeginChild("##controlBar", ImVec2(0, barHeight), false, ImGuiWindowFlags_NoScrollbar);

        // Adapter selector
        ImGui::TextColored(kText3, "ADAPTER");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(380.0f);
        if (m_devices.empty()) {
            ImGui::BeginDisabled();
            ImGui::BeginCombo("##deviceCombo", "No adapters detected");
            ImGui::EndCombo();
            ImGui::EndDisabled();
        } else if (ImGui::BeginCombo("##deviceCombo", m_devices[m_selectedDeviceIndex].description.c_str())) {
            for (int n = 0; n < static_cast<int>(m_devices.size()); n++) {
                const bool is_selected = (m_selectedDeviceIndex == n);
                if (ImGui::Selectable(m_devices[n].description.c_str(), is_selected)) {
                    m_selectedDeviceIndex = n;
                    clearCaptureView();
                    if (onDeviceSelected) onDeviceSelected(m_devices[n].name);
                }
                if (is_selected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        ImGui::SameLine(0.0f, 24.0f);
        ImGui::TextColored(kText3, "FILTER");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(260.0f);
        if (ImGui::InputTextWithHint("##bpfFilter", "tcp port 443",
                m_bpfFilter, sizeof(m_bpfFilter), ImGuiInputTextFlags_EnterReturnsTrue)) {
            std::string error;
            if (onBpfFilterRequested && onBpfFilterRequested(m_bpfFilter, error)) {
                m_captureStatus = m_bpfFilter[0] == '\0' ? "BPF filter cleared." : "BPF filter applied.";
                m_captureStatusIsError = false;
            } else {
                m_captureStatus = error.empty() ? "Unable to apply BPF filter." : error;
                m_captureStatusIsError = true;
            }
        }

        if (!m_captureStatus.empty()) {
            ImGui::SameLine(0.0f, 18.0f);
            ImGui::TextColored(m_captureStatusIsError ? kDanger : kSuccess, "%s", m_captureStatus.c_str());
        }

        ImGui::EndChild();
        ImGui::PopStyleVar(2);
        ImGui::PopStyleColor();

        // Subtle separator line below the control bar.
        const ImVec2 lineP = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddLine(
            lineP, ImVec2(lineP.x + ImGui::GetContentRegionAvail().x, lineP.y),
            ImGui::GetColorU32(kBorderSoft));
    }

    void GuiLayer::renderPacketTable() {
        ImGui::Begin("Live Packets");

        ImGui::Checkbox("Auto-scroll", &m_autoScroll);
        ImGui::SameLine();
        if (ImGui::Button("Clear capture")) {
            clearCaptureView();
        }
        ImGui::SameLine();
        ImGui::TextDisabled("%zu packets shown", m_packetHistory.size());

        if (m_packetFlowFilter) {
            ImGui::SameLine();
            ImGui::TextDisabled("|");
            ImGui::SameLine();
            ImGui::TextColored(kAccent, "Filtered: %s:%u",
                m_packetFlowFilter->dstIP.c_str(), m_packetFlowFilter->dstPort);
            ImGui::SameLine();
            if (ImGui::SmallButton("Clear filter")) {
                m_packetFlowFilter.reset();
            }
        }
        ImGui::Spacing();

        if (ImGui::BeginTable("PacketTable", 6, 
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {
            
            ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 105.0f);
            ImGui::TableSetupColumn("Source IP", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Dest IP", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Service/Info", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            std::vector<size_t> matchingPacketIndexes;
            if (m_packetFlowFilter) {
                matchingPacketIndexes.reserve(m_packetHistory.size());
                for (size_t index = 0; index < m_packetHistory.size(); ++index) {
                    if (core::FlowAggregator::matches(m_packetHistory[index], *m_packetFlowFilter)) {
                        matchingPacketIndexes.push_back(index);
                    }
                }
            }

            const int rowCount = m_packetFlowFilter
                ? static_cast<int>(matchingPacketIndexes.size())
                : static_cast<int>(m_packetHistory.size());

            // Use cli-pper for performance
            ImGuiListClipper clipper;
            clipper.Begin(rowCount);
            
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    const size_t packetIndex = m_packetFlowFilter
                        ? matchingPacketIndexes[static_cast<size_t>(i)]
                        : static_cast<size_t>(i);
                    const auto& p = m_packetHistory[packetIndex];
                    ImGui::TableNextRow();
                    
                    ImGui::TableSetColumnIndex(0);
                    const auto timestamp = std::chrono::sys_time<std::chrono::microseconds>{
                        std::chrono::microseconds{p.timestamp}
                    };
                    const auto seconds = std::chrono::floor<std::chrono::seconds>(timestamp);
                    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp - seconds).count();
                    const auto timeText = std::format("{:%H:%M:%S}.{:03}", seconds, milliseconds);
                    ImGui::TextUnformatted(timeText.c_str());
                    
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(p.srcIP.c_str());
                    
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(p.dstIP.c_str());
                    
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextColored(protocolColor(p.protocol), "%s", p.protocol.c_str());

                    ImGui::TableSetColumnIndex(4);
                    ImGui::Text("%u", p.length);

                    ImGui::TableSetColumnIndex(5);
                    if (!p.service.empty()) {
                        drawDot(serviceColor(p.service));
                        ImGui::SameLine();
                        ImGui::TextColored(kText1, "%s", p.service.c_str());
                        if (!p.sni.empty()) {
                            ImGui::SameLine();
                            ImGui::TextColored(kText3, "%s", p.sni.c_str());
                        }
                    } else if (!p.sni.empty()) {
                        ImGui::TextColored(kText3, "TLS");
                        ImGui::SameLine();
                        ImGui::TextColored(kText2, "%s", p.sni.c_str());
                    } else if (const auto hostname = m_hostnameCache.lookup(p.dstIP)) {
                        ImGui::TextColored(kText3, "host");
                        ImGui::SameLine();
                        ImGui::TextColored(kText2, "%s", hostname->c_str());
                    } else if (p.dstPort == 443 || p.srcPort == 443) {
                        ImGui::TextDisabled("HTTPS (encrypted)");
                    } else {
                        ImGui::TextDisabled("raw");
                    }
                }
            }

            if (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                ImGui::SetScrollHereY(1.0f);
            
            ImGui::EndTable();
        }
        ImGui::End();
    }

    void GuiLayer::renderFlowsTable() {
        ImGui::Begin("Flows");

        auto flows = m_flowAggregator.snapshot(currentUnixTimeMicroseconds());
        m_activeFlowCount = flows.size();
        std::unordered_map<std::string, core::GeoIPInfo> geoInfoByIp;
        uint64_t maxFlowBytes = 0;
        for (const auto& flow : flows) {
            if (!geoInfoByIp.contains(flow.key.dstIP)) {
                geoInfoByIp.emplace(flow.key.dstIP, m_geoIPResolver.lookup(flow.key.dstIP));
            }
            maxFlowBytes = std::max<uint64_t>(maxFlowBytes, flow.bytesUp + flow.bytesDown);
        }
        constexpr ImGuiTableFlags tableFlags = ImGuiTableFlags_ScrollY
            | ImGuiTableFlags_RowBg
            | ImGuiTableFlags_Borders
            | ImGuiTableFlags_Resizable
            | ImGuiTableFlags_Sortable;

        if (ImGui::BeginTable("FlowsTable", 9, tableFlags)) {
            ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Country", ImGuiTableColumnFlags_WidthFixed, 65.0f);
            ImGui::TableSetupColumn("Org", ImGuiTableColumnFlags_WidthFixed, 180.0f);
            ImGui::TableSetupColumn("Service", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Protocol:Port", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("Packets", ImGuiTableColumnFlags_WidthFixed, 75.0f);
            ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 90.0f);
            ImGui::TableSetupColumn("Rate", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending, 90.0f);
            ImGui::TableSetupColumn("Duration", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs(); sortSpecs && sortSpecs->SpecsDirty) {
                m_flowSortColumn = sortSpecs->Specs[0].ColumnIndex;
                m_flowSortAscending = sortSpecs->Specs[0].SortDirection == ImGuiSortDirection_Ascending;
                sortSpecs->SpecsDirty = false;
            }

            const auto organizationLabel = [](const core::GeoIPInfo& info) {
                if (info.organization.empty()) return std::string{"-"};
                return info.asn == 0
                    ? info.organization
                    : std::format("AS{} {}", info.asn, info.organization);
            };
            const auto compareFlows = [this, &geoInfoByIp, &organizationLabel](const core::Flow& left, const core::Flow& right) {
                const std::string& leftHost = left.hostname.empty() ? left.key.dstIP : left.hostname;
                const std::string& rightHost = right.hostname.empty() ? right.key.dstIP : right.hostname;
                const auto& leftGeo = geoInfoByIp.at(left.key.dstIP);
                const auto& rightGeo = geoInfoByIp.at(right.key.dstIP);
                const std::string leftCountry = leftGeo.country.empty() ? "-" : leftGeo.country;
                const std::string rightCountry = rightGeo.country.empty() ? "-" : rightGeo.country;
                const std::string leftOrganization = organizationLabel(leftGeo);
                const std::string rightOrganization = organizationLabel(rightGeo);
                const uint64_t leftBytes = left.bytesUp + left.bytesDown;
                const uint64_t rightBytes = right.bytesUp + right.bytesDown;

                int comparison = 0;
                switch (m_flowSortColumn) {
                case 0: comparison = leftHost.compare(rightHost); break;
                case 1: comparison = leftCountry.compare(rightCountry); break;
                case 2: comparison = leftOrganization.compare(rightOrganization); break;
                case 3: comparison = left.service.compare(right.service); break;
                case 4: comparison = std::tie(left.key.protocol, left.key.dstPort) < std::tie(right.key.protocol, right.key.dstPort) ? -1
                    : std::tie(right.key.protocol, right.key.dstPort) < std::tie(left.key.protocol, left.key.dstPort) ? 1 : 0; break;
                case 5: comparison = left.packets < right.packets ? -1 : left.packets > right.packets ? 1 : 0; break;
                case 6: comparison = leftBytes < rightBytes ? -1 : leftBytes > rightBytes ? 1 : 0; break;
                case 7: comparison = left.rateBytesPerSecond < right.rateBytesPerSecond ? -1
                    : left.rateBytesPerSecond > right.rateBytesPerSecond ? 1 : 0; break;
                case 8: comparison = (left.lastSeen - left.firstSeen) < (right.lastSeen - right.firstSeen) ? -1
                    : (left.lastSeen - left.firstSeen) > (right.lastSeen - right.firstSeen) ? 1 : 0; break;
                default: break;
                }
                if (comparison == 0) comparison = leftHost.compare(rightHost);
                return m_flowSortAscending ? comparison < 0 : comparison > 0;
            };
            std::sort(flows.begin(), flows.end(), compareFlows);

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(flows.size()));
            while (clipper.Step()) {
                for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                    const auto& flow = flows[static_cast<size_t>(index)];
                    const std::string& host = flow.hostname.empty() ? flow.key.dstIP : flow.hostname;
                    const auto& geoInfo = geoInfoByIp.at(flow.key.dstIP);
                    const std::string country = geoInfo.country.empty() ? "-" : geoInfo.country;
                    const std::string organization = organizationLabel(geoInfo);
                    const uint64_t totalBytes = flow.bytesUp + flow.bytesDown;
                    const bool selected = m_packetFlowFilter && *m_packetFlowFilter == flow.key;

                    ImGui::PushID(index);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    if (ImGui::Selectable(host.c_str(), selected,
                        ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                        m_packetFlowFilter = flow.key;
                    }
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(country.c_str());
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(organization.c_str());
                    ImGui::TableSetColumnIndex(3);
                    if (flow.service.empty()) {
                        ImGui::TextDisabled("--");
                    } else {
                        drawDot(serviceColor(flow.service));
                        ImGui::SameLine();
                        ImGui::TextColored(kText1, "%s", flow.service.c_str());
                    }
                    ImGui::TableSetColumnIndex(4);
                    const std::string protocolAndPort = std::format("{}:{}", flow.key.protocol, flow.key.dstPort);
                    ImGui::TextColored(protocolColor(flow.key.protocol), "%s", protocolAndPort.c_str());
                    ImGui::TableSetColumnIndex(5);
                    ImGui::Text("%llu", static_cast<unsigned long long>(flow.packets));
                    ImGui::TableSetColumnIndex(6);
                    // Bytes cell: number + a thin background bar showing share of the heaviest flow.
                    {
                        const std::string bytes = formatBytes(totalBytes);
                        const ImVec2 cellMin = ImGui::GetCursorScreenPos();
                        const float cellW = ImGui::GetContentRegionAvail().x;
                        const float barH = 4.0f;
                        const float fraction = maxFlowBytes == 0
                            ? 0.0f
                            : static_cast<float>(totalBytes) / static_cast<float>(maxFlowBytes);
                        ImDrawList* dl = ImGui::GetWindowDrawList();
                        const float trackY = cellMin.y + ImGui::GetTextLineHeight() + 2.0f;
                        dl->AddRectFilled(
                            ImVec2(cellMin.x, trackY),
                            ImVec2(cellMin.x + cellW, trackY + barH),
                            ImGui::GetColorU32(ImVec4(kAccent.x, kAccent.y, kAccent.z, 0.10f)),
                            barH * 0.5f);
                        dl->AddRectFilled(
                            ImVec2(cellMin.x, trackY),
                            ImVec2(cellMin.x + cellW * fraction, trackY + barH),
                            ImGui::GetColorU32(kAccent),
                            barH * 0.5f);
                        ImGui::TextUnformatted(bytes.c_str());
                    }
                    ImGui::TableSetColumnIndex(7);
                    const std::string rate = std::format("{}/s", formatBytes(static_cast<uint64_t>(flow.rateBytesPerSecond)));
                    ImGui::TextUnformatted(rate.c_str());
                    ImGui::TableSetColumnIndex(8);
                    const std::string duration = formatDuration(flow.firstSeen, flow.lastSeen);
                    ImGui::TextUnformatted(duration.c_str());
                    ImGui::PopID();
                }
            }

            ImGui::EndTable();
        }
        ImGui::End();
    }

    void GuiLayer::renderKpiStrip() {
        const float availW = ImGui::GetContentRegionAvail().x;
        const float spacing = 12.0f;
        const float tileW = std::max(150.0f, (availW - spacing * 3.0f) / 4.0f);
        const float tileH = 96.0f;

        struct Tile {
            const char* label;
            std::string value;
            std::string sub;
        };

        const std::string throughput = std::format("{:.2f}", m_currentMbps);
        const std::string flows = formatCount(m_activeFlowCount);
        const std::string packets = formatCount(m_totalPackets);
        const std::string topApp = m_topService.empty() ? std::string{"--"} : m_topService;
        const std::string topAppSub = m_topService.empty()
            ? std::string{"awaiting traffic"}
            : std::format("{} packets", m_topServiceCount);

        const std::array<Tile, 4> tiles = {{
            {"PACKETS",      packets,    "captured this session"},
            {"THROUGHPUT",   throughput + " MB/s", std::format("peak {:.2f} MB/s", m_peakMbps)},
            {"FLOWS",        flows,      "active conversations"},
            {"TOP SERVICE",  topApp,     topAppSub},
        }};

        ImGui::PushStyleColor(ImGuiCol_ChildBg, kBgSurface);
        ImGui::PushStyleColor(ImGuiCol_Border, kBorderSoft);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 16));
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(spacing, 0));

        for (size_t i = 0; i < tiles.size(); ++i) {
            const Tile& t = tiles[i];
            ImGui::PushID(static_cast<int>(i));
            if (ImGui::BeginChild("kpi", ImVec2(tileW, tileH), true,
                    ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
                ImGui::TextColored(kText3, "%s", t.label);
                ImGui::Spacing();
                if (m_fontHeadline) ImGui::PushFont(m_fontHeadline);
                ImGui::PushStyleColor(ImGuiCol_Text, kText1);
                // Headline value — clipped to one line.
                ImGui::TextUnformatted(t.value.c_str());
                ImGui::PopStyleColor();
                if (m_fontHeadline) ImGui::PopFont();
                ImGui::TextColored(kText2, "%s", t.sub.c_str());
            }
            ImGui::EndChild();
            ImGui::PopID();
            if (i + 1 < tiles.size()) ImGui::SameLine();
        }

        ImGui::PopStyleVar(4);
        ImGui::PopStyleColor(2);
    }

    void GuiLayer::renderCharts() {
        ImGui::Begin("Dashboard");

        renderKpiStrip();
        ImGui::Dummy(ImVec2(0, 8));

        // Bandwidth chart — minimal axes, filled area, single accent.
        ImGui::PushStyleColor(ImGuiCol_ChildBg, kBgSurface);
        ImGui::PushStyleColor(ImGuiCol_Border, kBorderSoft);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 16));

        const float chartHostH = 260.0f;
        if (ImGui::BeginChild("##bandwidthHost", ImVec2(0, chartHostH), true,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
            // Card header: title left, current/peak right.
            ImGui::TextColored(kText3, "BANDWIDTH");
            ImGui::SameLine();
            ImGui::TextColored(kText3, " — last 60 seconds");

            const std::string currentLabel = std::format("{:.2f} MB/s", m_currentMbps);
            const float labelWidth = ImGui::CalcTextSize(currentLabel.c_str()).x;
            ImGui::SameLine(ImGui::GetContentRegionAvail().x - labelWidth + ImGui::GetCursorPosX() - ImGui::GetStyle().ItemSpacing.x);
            ImGui::TextColored(kText1, "%s", currentLabel.c_str());

            ImGui::Dummy(ImVec2(0, 4));

            if (ImPlot::BeginPlot("##bandwidth", ImVec2(-1, -1),
                    ImPlotFlags_NoTitle | ImPlotFlags_NoMouseText | ImPlotFlags_NoLegend |
                    ImPlotFlags_NoBoxSelect | ImPlotFlags_NoFrame)) {
                ImPlot::SetupAxes(nullptr, nullptr,
                    ImPlotAxisFlags_NoLabel | ImPlotAxisFlags_NoTickLabels | ImPlotAxisFlags_NoTickMarks | ImPlotAxisFlags_AutoFit,
                    ImPlotAxisFlags_NoLabel | ImPlotAxisFlags_NoTickMarks | ImPlotAxisFlags_AutoFit);
                ImPlot::SetupAxisLimits(ImAxis_X1, glfwGetTime() - 60.0, glfwGetTime(), ImGuiCond_Always);

                if (!m_bandwidthData.Data.empty()) {
                    const size_t sampleCount = m_bandwidthData.Data.size();
                    const size_t start = sampleCount == static_cast<size_t>(m_bandwidthData.MaxSize)
                        ? static_cast<size_t>(m_bandwidthData.Offset)
                        : 0;
                    m_linearBandwidthTime.clear();
                    m_linearBandwidthData.clear();
                    m_linearBandwidthTime.reserve(sampleCount);
                    m_linearBandwidthData.reserve(sampleCount);
                    for (size_t i = 0; i < sampleCount; ++i) {
                        const size_t index = (start + i) % sampleCount;
                        m_linearBandwidthTime.push_back(m_bandwidthData.Time[index]);
                        m_linearBandwidthData.push_back(m_bandwidthData.Data[index]);
                    }
                    ImPlot::PlotShaded("MB/s",
                        m_linearBandwidthTime.data(),
                        m_linearBandwidthData.data(),
                        static_cast<int>(sampleCount), 0.0,
                        ImPlotSpec(ImPlotProp_FillColor, kAccent,
                                   ImPlotProp_FillAlpha, 0.18f));
                    ImPlot::PlotLine("MB/s",
                        m_linearBandwidthTime.data(),
                        m_linearBandwidthData.data(),
                        static_cast<int>(sampleCount),
                        ImPlotSpec(ImPlotProp_LineColor, kAccent,
                                   ImPlotProp_LineWeight, 1.75f));
                }
                ImPlot::EndPlot();
            }
        }
        ImGui::EndChild();
        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);

        ImGui::Dummy(ImVec2(0, 8));

        // Top Applications — clean list with dot, name, count, share bar.
        ImGui::PushStyleColor(ImGuiCol_ChildBg, kBgSurface);
        ImGui::PushStyleColor(ImGuiCol_Border, kBorderSoft);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 16));

        if (ImGui::BeginChild("##topApps", ImVec2(0, 0), true)) {
            ImGui::TextColored(kText3, "TOP SERVICES");
            ImGui::Dummy(ImVec2(0, 6));

            if (m_appCounts.empty()) {
                ImGui::TextColored(kText3, "Identified services will appear here once traffic is observed.");
            } else {
                std::vector<std::pair<std::string,int>> sorted(m_appCounts.begin(), m_appCounts.end());
                std::sort(sorted.begin(), sorted.end(),
                    [](const auto& a, const auto& b){ return a.second > b.second; });

                const int maxCount = sorted.front().second;
                const float nameCol = 180.0f;
                const float countCol = 70.0f;
                const float pctCol = 60.0f;

                for (const auto& [name, count] : sorted) {
                    const float fraction = maxCount == 0
                        ? 0.0f
                        : static_cast<float>(count) / static_cast<float>(maxCount);
                    const float share = m_totalPackets == 0
                        ? 0.0f
                        : static_cast<float>(count) / static_cast<float>(m_totalPackets);

                    drawDot(serviceColor(name));
                    ImGui::SameLine();
                    ImGui::TextColored(kText1, "%s", name.c_str());
                    ImGui::SameLine(nameCol);

                    // Subtle bar
                    const ImVec2 barP = ImGui::GetCursorScreenPos();
                    const float barW = ImGui::GetContentRegionAvail().x - countCol - pctCol;
                    const float barH = 6.0f;
                    const float trackY = barP.y + ImGui::GetTextLineHeight() * 0.5f - barH * 0.5f;
                    ImDrawList* dl = ImGui::GetWindowDrawList();
                    dl->AddRectFilled(
                        ImVec2(barP.x, trackY),
                        ImVec2(barP.x + barW, trackY + barH),
                        ImGui::GetColorU32(kBgInput), barH * 0.5f);
                    dl->AddRectFilled(
                        ImVec2(barP.x, trackY),
                        ImVec2(barP.x + barW * fraction, trackY + barH),
                        ImGui::GetColorU32(kAccent), barH * 0.5f);
                    ImGui::Dummy(ImVec2(barW, ImGui::GetTextLineHeight()));

                    ImGui::SameLine();
                    ImGui::TextColored(kText1, "%d", count);
                    ImGui::SameLine(ImGui::GetContentRegionAvail().x + ImGui::GetCursorPosX() - pctCol);
                    ImGui::TextColored(kText3, "%.1f%%", share * 100.0f);
                }
            }
        }
        ImGui::EndChild();
        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);

        ImGui::End();
    }

} // namespace ui
