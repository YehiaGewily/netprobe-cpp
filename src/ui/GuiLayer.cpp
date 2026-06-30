#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "ui/EmbeddedIcon.hpp"
#include "core/DNSParser.hpp"
#include "core/ProtocolParser.hpp"
#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"
#include "nfd.h"
#include <GLFW/glfw3.h>
#include <cmath>
#include <filesystem>
#include <iostream>

namespace ui {

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

        // Title-bar and taskbar icon — the embedded .ico covers Explorer /
        // shortcuts, but GLFW windows need an explicit set call to override
        // the default OS window icon while the app is running.
        GLFWimage icons[3];
        icons[0] = {kEmbeddedIcon16Size, kEmbeddedIcon16Size,
            const_cast<unsigned char*>(kEmbeddedIcon16Pixels)};
        icons[1] = {kEmbeddedIcon32Size, kEmbeddedIcon32Size,
            const_cast<unsigned char*>(kEmbeddedIcon32Pixels)};
        icons[2] = {kEmbeddedIcon48Size, kEmbeddedIcon48Size,
            const_cast<unsigned char*>(kEmbeddedIcon48Pixels)};
        glfwSetWindowIcon(m_window, 3, icons);

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
        const std::filesystem::path mono     = "C:/Windows/Fonts/consola.ttf";

        if (std::filesystem::exists(regular)) {
            m_fontDefault  = io.Fonts->AddFontFromFileTTF(regular.string().c_str(), 15.0f, &cfg);
            m_fontSmall    = io.Fonts->AddFontFromFileTTF(regular.string().c_str(), 12.0f, &cfg);
            const auto& semiPath = std::filesystem::exists(semibold) ? semibold : regular;
            m_fontHeadline = io.Fonts->AddFontFromFileTTF(semiPath.string().c_str(), 28.0f, &cfg);
            m_fontBrand    = io.Fonts->AddFontFromFileTTF(semiPath.string().c_str(), 16.0f, &cfg);
            m_fontMono     = std::filesystem::exists(mono)
                ? io.Fonts->AddFontFromFileTTF(mono.string().c_str(), 13.0f, &cfg)
                : m_fontDefault;
        } else {
            // Fall back to the bundled bitmap font if Segoe UI is unavailable.
            m_fontDefault  = io.Fonts->AddFontDefault();
            m_fontSmall    = m_fontDefault;
            m_fontHeadline = m_fontDefault;
            m_fontBrand    = m_fontDefault;
            m_fontMono     = m_fontDefault;
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
            if (m_packetHistory.size() >= maxPacketHistory) {
                m_packetHistory.pop_front();
                if (m_selectedPacketIndex >= 0) --m_selectedPacketIndex;
            }
            m_packetHistory.push_back({*packetOpt, parsed});

            ++m_totalPackets;
            m_bytesThisSec += parsed.length;
            if (!parsed.service.empty()) {
                m_appCounts[parsed.service]++;
            }

            count++;
        }

        // Update bandwidth chart every 0.5s.
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

                ImGuiID flowsId, rightId;
                ImGui::DockBuilderSplitNode(bottomId, ImGuiDir_Left, 0.45f, &flowsId, &rightId);

                ImGuiID packetsId, detailId;
                ImGui::DockBuilderSplitNode(rightId, ImGuiDir_Up, 0.55f, &packetsId, &detailId);

                ImGui::DockBuilderDockWindow("Dashboard", topId);
                ImGui::DockBuilderDockWindow("Flows", flowsId);
                ImGui::DockBuilderDockWindow("Live Packets", packetsId);
                ImGui::DockBuilderDockWindow("Packet Detail", detailId);
                ImGui::DockBuilderFinish(dockspaceId);
            }
        }
        ImGui::DockSpace(dockspaceId, ImVec2(0, 0), ImGuiDockNodeFlags_None);

        ImGui::End();

        renderCharts();
        renderFlowsTable();
        renderPacketTable();
        renderPacketDetail();
    }

    void GuiLayer::setDevices(const std::vector<DeviceInfo>& devices) {
        m_devices = devices;
    }

    void GuiLayer::clearCaptureView() {
        m_packetHistory.clear();
        m_selectedPacketIndex = -1;
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

} // namespace ui
