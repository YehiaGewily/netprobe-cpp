#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "ui/EmbeddedIcon.hpp"
#include "imgui.h"
#include "imgui_internal.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"
#include "nfd.h"
#include <GLFW/glfw3.h>
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>

namespace ui {

    GuiLayer::GuiLayer(core::PacketQueue& queue) : m_queue(queue) {}

    GuiLayer::~GuiLayer() {
        // Persisting preferences touches the filesystem, and an exception
        // escaping a destructor terminates the process. Losing the saved
        // window geometry is an acceptable outcome; crashing on exit is not.
        try {
            captureWindowGeometry();
            saveSettings();
        } catch (...) {
            // Reported with fputs rather than iostreams: this runs during
            // shutdown, where anything that can throw defeats the point.
            std::fputs("NetProbe: could not save window geometry or preferences.\n", stderr);
        }

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

        // Settings are needed before window creation: they carry the saved
        // window geometry and maximized state from the previous run.
        loadSettings();

        const char* glsl_version = "#version 130";
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
        glfwWindowHint(GLFW_VISIBLE, GLFW_FALSE);
        if (m_savedWindowMaximized) glfwWindowHint(GLFW_MAXIMIZED, GLFW_TRUE);

        // A saved size is already in physical pixels; the default size is
        // authored for 100% scale and multiplied by the primary monitor's
        // content scale so first launch isn't tiny on high-DPI displays.
        int width = 1440, height = 900;
        if (m_savedWindowW > 0 && m_savedWindowH > 0) {
            width = std::clamp(m_savedWindowW, 800, 16384);
            height = std::clamp(m_savedWindowH, 500, 16384);
        } else if (GLFWmonitor* primary = glfwGetPrimaryMonitor()) {
            float scaleX = 1.0f, scaleY = 1.0f;
            glfwGetMonitorContentScale(primary, &scaleX, &scaleY);
            width = static_cast<int>(width * scaleX);
            height = static_cast<int>(height * scaleY);
        }

        m_window = glfwCreateWindow(width, height, "NetProbe  -  Network Analyzer", nullptr, nullptr);
        if (!m_window) {
            glfwTerminate();
            return false;
        }

        // Restore the previous window position, but only when its center still
        // falls on a connected monitor — displays come and go between runs.
        if (m_hasSavedWindowPos && !m_savedWindowMaximized) {
            int monitorCount = 0;
            GLFWmonitor** monitors = glfwGetMonitors(&monitorCount);
            const int centerX = m_savedWindowX + width / 2;
            const int centerY = m_savedWindowY + height / 2;
            for (int i = 0; i < monitorCount; ++i) {
                int mx, my, mw, mh;
                glfwGetMonitorWorkarea(monitors[i], &mx, &my, &mw, &mh);
                if (centerX >= mx && centerX < mx + mw && centerY >= my && centerY < my + mh) {
                    glfwSetWindowPos(m_window, m_savedWindowX, m_savedWindowY);
                    break;
                }
            }
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
        glfwShowWindow(m_window);

        glfwMakeContextCurrent(m_window);
        glfwSwapInterval(1); // Enable vsync
        glfwSetWindowUserPointer(m_window, this);

        // Per-monitor DPI: pick up the content scale of whichever monitor the
        // window actually landed on, and re-theme when it moves to another.
        float contentScale = 1.0f;
        glfwGetWindowContentScale(m_window, &contentScale, nullptr);
        if (contentScale > 0.0f) m_contentScale = contentScale;
        glfwSetWindowContentScaleCallback(m_window,
            [](GLFWwindow* window, float xScale, float) {
                auto* gui = static_cast<GuiLayer*>(glfwGetWindowUserPointer(window));
                if (gui && xScale > 0.0f && std::abs(xScale - gui->m_contentScale) > 0.01f) {
                    gui->m_contentScale = xScale;
                    gui->applyTheme();
                }
            });
        glfwSetDropCallback(m_window, [](GLFWwindow* window, int pathCount, const char** paths) {
            auto* gui = static_cast<GuiLayer*>(glfwGetWindowUserPointer(window));
            if (gui && pathCount > 0 && paths[0]) {
                gui->openPcapFile(paths[0]);
            }
        });

        m_nfdInitialized = NFD_Init() == NFD_OKAY;
        if (!m_nfdInitialized) {
            std::cerr << "Native file dialog is unavailable: " << NFD_GetError() << '\n';
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

    void GuiLayer::loadSettings() {
        std::ifstream file("netprobe-settings.ini");
        if (!file) return;
        std::string line;
        while (std::getline(file, line)) {
            const auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            const std::string key = line.substr(0, eq);
            const std::string value = line.substr(eq + 1);
            if (key == "theme") {
                m_darkTheme = value != "light";
            } else if (key == "scale") {
                try {
                    m_uiScale = std::clamp(std::stof(value), 0.75f, 1.5f);
                } catch (...) {
                    m_uiScale = 1.0f;
                }
            } else if (key == "window") {
                int x = 0, y = 0, w = 0, h = 0, maximized = 0;
                // Extracted rather than scanf'd: type-safe, and it avoids the
                // MSVC deprecation of sscanf without reaching for the
                // Windows-only sscanf_s.
                std::istringstream fields(value);
                if (fields >> x >> y >> w >> h >> maximized) {
                    m_savedWindowX = x;
                    m_savedWindowY = y;
                    m_savedWindowW = w;
                    m_savedWindowH = h;
                    m_savedWindowMaximized = maximized != 0;
                    m_hasSavedWindowPos = true;
                }
            }
        }
    }

    void GuiLayer::saveSettings() const {
        std::ofstream file("netprobe-settings.ini", std::ios::trunc);
        if (!file) return;
        file << "theme=" << (m_darkTheme ? "dark" : "light") << '\n';
        file << "scale=" << m_uiScale << '\n';
        if (m_savedWindowW > 0 && m_savedWindowH > 0) {
            file << "window=" << m_savedWindowX << ' ' << m_savedWindowY << ' '
                 << m_savedWindowW << ' ' << m_savedWindowH << ' '
                 << (m_savedWindowMaximized ? 1 : 0) << '\n';
        }
    }

    void GuiLayer::captureWindowGeometry() {
        if (!m_window) return;
        m_savedWindowMaximized = glfwGetWindowAttrib(m_window, GLFW_MAXIMIZED) == GLFW_TRUE;
        // While maximized (or minimized) the current rect is not the one worth
        // restoring — keep the last normal geometry already recorded.
        if (m_savedWindowMaximized
            || glfwGetWindowAttrib(m_window, GLFW_ICONIFIED) == GLFW_TRUE) {
            return;
        }
        glfwGetWindowPos(m_window, &m_savedWindowX, &m_savedWindowY);
        glfwGetWindowSize(m_window, &m_savedWindowW, &m_savedWindowH);
        m_hasSavedWindowPos = true;
    }

    void GuiLayer::setStatus(std::string message, bool isError) {
        m_captureStatus = std::move(message);
        m_captureStatusIsError = isError;
        m_captureStatusTime = glfwGetTime();
    }

    void GuiLayer::applyTheme() {
        applyPalette(m_darkTheme);

        ImGuiStyle& style = ImGui::GetStyle();
        // Rebuild from defaults so repeated calls (theme toggle, monitor DPI
        // change) never compound the ScaleAllSizes multiplication below.
        style = ImGuiStyle();
        style.FontScaleMain = m_uiScale * m_contentScale;

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
        c[ImGuiCol_FrameBgHovered]        = kBgHover;
        c[ImGuiCol_FrameBgActive]         = kBgActive;
        c[ImGuiCol_TitleBg]               = kBgBase;
        c[ImGuiCol_TitleBgActive]         = kBgBase;
        c[ImGuiCol_TitleBgCollapsed]      = kBgBase;
        c[ImGuiCol_MenuBarBg]             = kBgBase;
        c[ImGuiCol_ScrollbarBg]           = ImVec4(0, 0, 0, 0);
        c[ImGuiCol_ScrollbarGrab]         = kBgActive;
        c[ImGuiCol_ScrollbarGrabHovered]  = kBorder;
        c[ImGuiCol_ScrollbarGrabActive]   = kAccentSoft;
        c[ImGuiCol_CheckMark]             = kAccent;
        c[ImGuiCol_SliderGrab]            = kAccent;
        c[ImGuiCol_SliderGrabActive]      = kAccent;
        c[ImGuiCol_Button]                = kBgInput;
        c[ImGuiCol_ButtonHovered]         = kBgHover;
        c[ImGuiCol_ButtonActive]          = kBgActive;
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
        c[ImGuiCol_TableRowBgAlt]         = kIsDarkTheme
            ? ImVec4(1, 1, 1, 0.015f)
            : ImVec4(0, 0, 0, 0.020f);
        c[ImGuiCol_TextSelectedBg]        = kAccentSoft;
        c[ImGuiCol_NavHighlight]          = kAccent;

        // All style metrics above are authored at 100% scale; stretch them to
        // the monitor's DPI so padding and spacing match the scaled fonts.
        style.ScaleAllSizes(m_contentScale);

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
        pc[ImPlotCol_AxisGrid]     = ImVec4(kBorder.x, kBorder.y, kBorder.z, 0.60f);
        pc[ImPlotCol_AxisText]     = kText3;
        pc[ImPlotCol_TitleText]    = kText1;
        pc[ImPlotCol_LegendBg]     = kBgElevated;
        pc[ImPlotCol_LegendBorder] = kBorderSoft;
        pc[ImPlotCol_LegendText]   = kText1;
    }

    void GuiLayer::run() {
        while (!glfwWindowShouldClose(m_window)) {
            // While minimized there is nothing to draw: keep draining the
            // packet queue at a low rate so counters and flows stay current,
            // but skip rendering entirely.
            if (glfwGetWindowAttrib(m_window, GLFW_ICONIFIED) == GLFW_TRUE) {
                glfwWaitEventsTimeout(0.1);
                processQueue();
                continue;
            }

            // Frame pacing: run at full (vsync) rate only while live traffic
            // is streaming or the user recently interacted. Otherwise sleep on
            // the event queue — any input wakes the loop immediately, so the
            // UI stays responsive while an idle window stops burning CPU/GPU.
            const bool streaming = m_captureActive && !m_capturePaused;
            const bool recentInput = glfwGetTime() - m_lastInputTime < 0.75;
            if (streaming || recentInput) {
                glfwPollEvents();
            } else {
                glfwWaitEventsTimeout(1.0 / 15.0);
            }
            processQueue();

            // Track the last normal (non-maximized) window rect so it can be
            // persisted on exit.
            captureWindowGeometry();

            ImGui_ImplOpenGL3_NewFrame();
            ImGui_ImplGlfw_NewFrame();
            ImGui::NewFrame();

            const ImGuiIO& io = ImGui::GetIO();
            if (io.MouseDelta.x != 0.0f || io.MouseDelta.y != 0.0f
                || io.MouseWheel != 0.0f || io.MouseWheelH != 0.0f
                || ImGui::IsAnyMouseDown() || io.WantTextInput) {
                m_lastInputTime = glfwGetTime();
            }

            renderUI();

            ImGui::Render();
            int display_w, display_h;
            glfwGetFramebufferSize(m_window, &display_w, &display_h);
            glViewport(0, 0, display_w, display_h);
            glClearColor(kBgBase.x, kBgBase.y, kBgBase.z, 1.00f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

            glfwSwapBuffers(m_window);
        }
    }

    void GuiLayer::setPaused(bool paused) {
        if (m_capturePaused == paused) return;
        m_capturePaused = paused;
        if (!paused) {
            // Packets that piled up while paused are stale — the engine
            // retains them for PCAP export, but the live view should resume
            // with fresh traffic instead of replaying the backlog.
            m_queue.clear();
            m_bytesThisSec = 0;
            m_tcpBytesThisSec = 0;
            m_udpBytesThisSec = 0;
            m_lastUpdateTime = glfwGetTime();
        }
    }

    void GuiLayer::linearizeBuffer(const ScrollingBuffer& buffer,
        std::vector<float>& time, std::vector<float>& data) {
        time.clear();
        data.clear();
        const size_t sampleCount = buffer.Data.size();
        if (sampleCount == 0) return;
        const size_t start = sampleCount == static_cast<size_t>(buffer.MaxSize)
            ? static_cast<size_t>(buffer.Offset)
            : 0;
        time.reserve(sampleCount);
        data.reserve(sampleCount);
        for (size_t i = 0; i < sampleCount; ++i) {
            const size_t index = (start + i) % sampleCount;
            time.push_back(buffer.Time[index]);
            data.push_back(buffer.Data[index]);
        }
    }

    void GuiLayer::processQueue() {
        if (m_capturePaused) return;

        // Process up to 1000 packets per frame to maintain responsiveness
        constexpr size_t maxPacketHistory = 10'000;
        int count = 0;
        double currentTime = glfwGetTime();

        while (count < 1000) {
            auto packetOpt = m_queue.try_pop();
            if (!packetOpt) break;

            // Decode, recover cross-packet SNI, harvest DNS answers, attribute
            // the owning process, and fold the packet into its flow.
            auto analyzed = m_session.feed(*packetOpt);

            // Keep the visual history bounded while retaining all-time counters separately.
            if (m_packetHistory.size() >= maxPacketHistory) {
                m_packetHistory.pop_front();
                if (m_selectedPacketIndex >= 0) --m_selectedPacketIndex;
            }
            m_packetHistory.push_back({*packetOpt, std::move(analyzed.parsed),
                std::move(analyzed.process)});
            ++m_packetHistoryVersion;
            const core::ParsedPacket& stored = m_packetHistory.back().parsed;

            ++m_totalPackets;
            m_bytesThisSec += stored.length;
            if (stored.protocol == "TCP") {
                m_tcpBytesThisSec += stored.length;
            } else if (stored.protocol == "UDP") {
                m_udpBytesThisSec += stored.length;
            }
            m_protocolCounts[stored.protocol]++;
            m_protocolBytes[stored.protocol] += stored.length;
            if (!stored.service.empty()) {
                m_appCounts[stored.service]++;
            }

            count++;
        }

        // Update bandwidth chart every 0.5s.
        if (currentTime - m_lastUpdateTime >= 0.5) {
            const auto toMbps = [](uint64_t bytes) {
                return static_cast<float>(bytes) / (1024.0f * 1024.0f) / 0.5f;
            };
            const float mbps = toMbps(m_bytesThisSec);
            m_bandwidthData.AddPoint((float)currentTime, mbps);
            m_tcpBandwidth.AddPoint((float)currentTime, toMbps(m_tcpBytesThisSec));
            m_udpBandwidth.AddPoint((float)currentTime, toMbps(m_udpBytesThisSec));
            m_currentMbps = mbps;
            if (mbps > m_peakMbps) m_peakMbps = mbps;
            m_bytesThisSec = 0;
            m_tcpBytesThisSec = 0;
            m_udpBytesThisSec = 0;
            m_lastUpdateTime = currentTime;
        }

        // Refresh KPI cache (cheap derived values).
        m_topService.clear();
        m_topServiceCount = 0;
        for (const auto& [name, c] : m_appCounts) {
            if (c > m_topServiceCount) { m_topService = name; m_topServiceCount = c; }
        }
    }

    void GuiLayer::handleShortcuts() {
        ImGuiIO& io = ImGui::GetIO();
        if (ImGui::IsKeyChordPressed(ImGuiMod_Ctrl | ImGuiKey_O)) {
            openPcapDialog();
        }
        // Text-editing keys only act as shortcuts when no input field owns them.
        if (!io.WantTextInput) {
            if (ImGui::IsKeyPressed(ImGuiKey_Space, false)) {
                setPaused(!m_capturePaused);
            }
            if (ImGui::IsKeyPressed(ImGuiKey_Slash, false)) {
                m_focusDisplayFilter = true;
            }
        }
    }

    void GuiLayer::renderUI() {
        handleShortcuts();

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
        renderEncryptedDnsNotice();

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
                ImGui::DockBuilderDockWindow("Statistics", topId);
                ImGui::DockBuilderDockWindow("Flows", flowsId);
                ImGui::DockBuilderDockWindow("Live Packets", packetsId);
                ImGui::DockBuilderDockWindow("Packet Detail", detailId);
                ImGui::DockBuilderFinish(dockspaceId);

                // Keep the Dashboard tab in front of Statistics on first run.
                if (ImGuiDockNode* topNode = ImGui::DockBuilderGetNode(topId)) {
                    topNode->SelectedTabId = ImHashStr("Dashboard");
                }
            }
        }
        ImGui::DockSpace(dockspaceId, ImVec2(0, 0), ImGuiDockNodeFlags_None);

        ImGui::End();

        renderCharts();
        renderStatsView();
        renderFlowsTable();
        renderPacketTable();
        renderPacketDetail();
    }

    void GuiLayer::setDevices(const std::vector<DeviceInfo>& devices) {
        m_devices = devices;
    }

    void GuiLayer::clearCaptureView() {
        m_packetHistory.clear();
        ++m_packetHistoryVersion;
        m_filteredPacketIndexes.clear();
        m_filterCacheHistoryVersion = UINT64_MAX;
        m_flowsCache.clear();
        m_flowGeoCache.clear();
        m_lastFlowsRefresh = -1.0;
        m_maxFlowBytes = 0;
        m_activeFlowCount = 0;
        m_selectedPacketIndex = -1;
        m_appCounts.clear();
        m_protocolCounts.clear();
        m_protocolBytes.clear();
        m_session.clear();
        m_packetFlowFilter.reset();
        m_flowRateHistory.Erase();
        m_flowRateKey.reset();
        m_bandwidthData.Erase();
        m_tcpBandwidth.Erase();
        m_udpBandwidth.Erase();
        m_bytesThisSec = 0;
        m_tcpBytesThisSec = 0;
        m_udpBytesThisSec = 0;
        m_totalPackets = 0;
        m_lastUpdateTime = glfwGetTime();
    }

    void GuiLayer::openPcapFile(const std::string& path) {
        if (path.empty()) return;
        clearCaptureView();
        setPaused(false);
        m_captureActive = false;
        if (onPcapFileSelected) {
            onPcapFileSelected(path);
        }
    }

    void GuiLayer::openPcapDialog() {
        if (!m_nfdInitialized) return;
        const nfdu8filteritem_t filters[] = {
            {"Packet captures", "pcap,pcapng,cap"},
        };
        nfdu8char_t* selectedPath = nullptr;
        const nfdresult_t result = NFD_OpenDialogU8(&selectedPath, filters, 1, nullptr);
        if (result == NFD_OKAY) {
            openPcapFile(selectedPath);
            NFD_FreePathU8(selectedPath);
        } else if (result == NFD_ERROR) {
            std::cerr << "Unable to open file dialog: " << NFD_GetError() << '\n';
        }
    }

    void GuiLayer::renderTopBar() {
        if (!ImGui::BeginMenuBar()) return;

        // Brand
        if (m_fontBrand) ImGui::PushFont(m_fontBrand);
        ImGui::TextColored(kText1, "NetProbe");
        if (m_fontBrand) ImGui::PopFont();

        // Capture state indicator: pulsing green when live traffic is being
        // consumed, amber when paused, muted when idle.
        ImGui::SameLine(0.0f, 14.0f);
        {
            const bool paused = m_capturePaused;
            const bool live = !paused && m_currentMbps > 0.0001f;
            const float pulse = live
                ? 0.55f + 0.45f * (0.5f + 0.5f * std::sin(static_cast<float>(glfwGetTime()) * 3.0f))
                : 1.0f;
            const ImVec4 dotColor = paused
                ? kWarning
                : live
                    ? ImVec4(kSuccess.x, kSuccess.y, kSuccess.z, pulse)
                    : ImVec4(kText3.x, kText3.y, kText3.z, 1.0f);
            const float r = 4.0f;
            const ImVec2 cursor = ImGui::GetCursorScreenPos();
            ImGui::GetWindowDrawList()->AddCircleFilled(
                ImVec2(cursor.x + r, cursor.y + ImGui::GetTextLineHeight() * 0.5f),
                r, ImGui::GetColorU32(dotColor));
            ImGui::Dummy(ImVec2(r * 2.0f + 6.0f, ImGui::GetTextLineHeight()));
            ImGui::SameLine();
            const char* label = paused ? "Paused" : live ? "Live" : "Idle";
            ImGui::TextColored(paused || live ? kText2 : kText3, "%s", label);
        }

        ImGui::SameLine(0.0f, 18.0f);
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open PCAP...", "Ctrl+O", false, m_nfdInitialized)) {
                openPcapDialog();
            }
            if (ImGui::MenuItem("Save PCAP...", nullptr, false, m_nfdInitialized)) {
                const nfdu8filteritem_t filters[] = {
                    {"Packet captures", "pcap"},
                };
                nfdu8char_t* selectedPath = nullptr;
                const nfdresult_t result = NFD_SaveDialogU8(
                    &selectedPath, filters, 1, nullptr, "netprobe-session.pcap");
                if (result == NFD_OKAY) {
                    std::string error;
                    if (onPcapSaveRequested && onPcapSaveRequested(selectedPath, error)) {
                        setStatus("PCAP session saved.", false);
                    } else {
                        setStatus(error.empty() ? "Unable to save the PCAP session." : error, true);
                    }
                    NFD_FreePathU8(selectedPath);
                } else if (result == NFD_ERROR) {
                    setStatus(NFD_GetError() ? NFD_GetError() : "Unable to open the save dialog.", true);
                }
            }
            if (ImGui::MenuItem("Export Flows CSV...", nullptr, false, m_nfdInitialized)) {
                const nfdu8filteritem_t filters[] = {
                    {"CSV", "csv"},
                };
                nfdu8char_t* selectedPath = nullptr;
                const nfdresult_t result = NFD_SaveDialogU8(
                    &selectedPath, filters, 1, nullptr, "netprobe-flows.csv");
                if (result == NFD_OKAY) {
                    std::string error;
                    if (exportFlowsCsv(selectedPath, error)) {
                        setStatus("Flows exported to CSV.", false);
                    } else {
                        setStatus(error.empty() ? "Unable to export flows." : error, true);
                    }
                    NFD_FreePathU8(selectedPath);
                } else if (result == NFD_ERROR) {
                    setStatus(NFD_GetError() ? NFD_GetError() : "Unable to open the save dialog.", true);
                }
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Exit", "Alt+F4")) glfwSetWindowShouldClose(m_window, true);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            if (ImGui::MenuItem("Dark theme", nullptr, m_darkTheme) && !m_darkTheme) {
                m_darkTheme = true;
                applyTheme();
                saveSettings();
            }
            if (ImGui::MenuItem("Light theme", nullptr, !m_darkTheme) && m_darkTheme) {
                m_darkTheme = false;
                applyTheme();
                saveSettings();
            }
            ImGui::Separator();
            if (ImGui::BeginMenu("UI scale")) {
                constexpr float scales[] = {0.9f, 1.0f, 1.1f, 1.25f};
                const char* labels[] = {"90%", "100%", "110%", "125%"};
                for (int i = 0; i < 4; ++i) {
                    const bool selected = std::abs(m_uiScale - scales[i]) < 0.01f;
                    if (ImGui::MenuItem(labels[i], nullptr, selected) && !selected) {
                        m_uiScale = scales[i];
                        ImGui::GetStyle().FontScaleMain = m_uiScale;
                        saveSettings();
                    }
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
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
        ImGui::SetNextItemWidth(scaled(300.0f));
        if (m_devices.empty()) {
            ImGui::BeginDisabled();
            ImGui::BeginCombo("##deviceCombo", "No adapters detected");
            ImGui::EndCombo();
            ImGui::EndDisabled();
        } else if (ImGui::BeginCombo("##deviceCombo", m_devices[m_selectedDeviceIndex].displayLabel().c_str())) {
            for (int n = 0; n < static_cast<int>(m_devices.size()); n++) {
                const bool is_selected = (m_selectedDeviceIndex == n);
                if (ImGui::Selectable(m_devices[n].displayLabel().c_str(), is_selected)) {
                    m_selectedDeviceIndex = n;
                    clearCaptureView();
                    setPaused(false);
                    if (onDeviceSelected) {
                        onDeviceSelected(m_devices[n].name);
                        m_captureActive = true;
                        setStatus("Capture started.", false);
                    }
                }
                if (is_selected) ImGui::SetItemDefaultFocus();
            }
            ImGui::EndCombo();
        }

        // Start / Stop / Pause capture controls.
        ImGui::SameLine(0.0f, 10.0f);
        if (m_captureActive) {
            ImGui::PushStyleColor(ImGuiCol_Text, kDanger);
            if (ImGui::Button("Stop")) {
                if (onCaptureStopRequested) onCaptureStopRequested();
                m_captureActive = false;
                setStatus("Capture stopped.", false);
            }
            ImGui::PopStyleColor();
        } else {
            ImGui::BeginDisabled(m_devices.empty());
            ImGui::PushStyleColor(ImGuiCol_Text, kSuccess);
            if (ImGui::Button("Start")) {
                clearCaptureView();
                setPaused(false);
                if (onDeviceSelected) {
                    onDeviceSelected(m_devices[m_selectedDeviceIndex].name);
                    m_captureActive = true;
                    setStatus("Capture started.", false);
                }
            }
            ImGui::PopStyleColor();
            ImGui::EndDisabled();
        }
        ImGui::SetItemTooltip(m_captureActive
            ? "Stop the live capture (retained packets stay available for export)"
            : "Start capturing on the selected adapter");

        ImGui::SameLine(0.0f, 6.0f);
        if (ImGui::Button(m_capturePaused ? "Resume" : "Pause")) {
            setPaused(!m_capturePaused);
        }
        ImGui::SetItemTooltip("Freeze the live view without stopping capture (Space)");

        ImGui::SameLine(0.0f, 24.0f);
        ImGui::TextColored(kText3, "FILTER");
        ImGui::SameLine();
        ImGui::SetNextItemWidth(scaled(240.0f));
        if (ImGui::InputTextWithHint("##bpfFilter", "tcp port 443",
                m_bpfFilter, sizeof(m_bpfFilter), ImGuiInputTextFlags_EnterReturnsTrue)) {
            std::string error;
            if (onBpfFilterRequested && onBpfFilterRequested(m_bpfFilter, error)) {
                setStatus(m_bpfFilter[0] == '\0' ? "BPF filter cleared." : "BPF filter applied.", false);
            } else {
                setStatus(error.empty() ? "Unable to apply BPF filter." : error, true);
            }
        }
        ImGui::SetItemTooltip("Capture filter (BPF syntax) — press Enter to apply.\nOnly affects what is captured, not what is shown.");

        // Status messages expire after a few seconds instead of lingering
        // until the next action replaces them.
        if (!m_captureStatus.empty() && glfwGetTime() - m_captureStatusTime > 6.0) {
            m_captureStatus.clear();
        }
        if (!m_captureStatus.empty()) {
            ImGui::SameLine(0.0f, 18.0f);
            ImGui::TextColored(m_captureStatusIsError ? kDanger : kSuccess, "%s", m_captureStatus.c_str());
        }

        // Right-aligned overrun badge so users see when the UI is dropping.
        if (const size_t dropped = m_queue.droppedPackets(); dropped > 0) {
            const std::string badge = formatCount(dropped) + " dropped";
            const float w = ImGui::CalcTextSize(badge.c_str()).x;
            ImGui::SameLine(ImGui::GetContentRegionMax().x - w - 18.0f);
            ImGui::TextColored(kWarning, "%s", badge.c_str());
            ImGui::SetItemTooltip("Packets evicted from the UI queue because capture outpaced the display.\nThe oldest packets are dropped first; counters keep running.");
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

    bool GuiLayer::encryptedDnsDominates() const {
        // A handful of DoH packets alongside healthy plaintext DNS is normal.
        // The notice is for the case where name resolution has genuinely moved
        // off the wire and the hostname columns are going to stay empty.
        //
        // The bar is low deliberately: a DoH connection is identified by its
        // ClientHello SNI, and browsers reuse one connection for every lookup,
        // so a handful of sightings can already mean all resolution is hidden.
        constexpr uint64_t minimumEvidence = 3;
        return m_session.encryptedDnsPackets() >= minimumEvidence
            && m_session.encryptedDnsPackets() > m_session.plaintextDnsResponses() * 2;
    }

    void GuiLayer::renderEncryptedDnsNotice() {
        // ECH alone is not banner-worthy — most Cloudflare-fronted domains
        // advertise it, so it would show on nearly every capture. It is reported
        // as a standing fact in the Statistics view instead.
        const bool show = !m_dnsNoticeDismissed && encryptedDnsDominates();
        if (!show) return;

        ImGui::PushStyleColor(ImGuiCol_ChildBg,
            ImVec4(kWarning.x, kWarning.y, kWarning.z, kIsDarkTheme ? 0.10f : 0.16f));
        ImGui::PushStyleColor(ImGuiCol_Border,
            ImVec4(kWarning.x, kWarning.y, kWarning.z, 0.45f));
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 8.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14, 8));

        const float height = ImGui::GetFrameHeight() + 20.0f;
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 18.0f);
        ImGui::BeginChild("##dnsNotice",
            ImVec2(ImGui::GetContentRegionAvail().x - 18.0f, height), true,
            ImGuiWindowFlags_NoScrollbar);

        drawDot(kWarning, 4.0f);
        ImGui::SameLine();
        ImGui::TextColored(kText1, "Encrypted DNS in use.");
        ImGui::SameLine();
        ImGui::TextColored(kText2, m_session.echAdvertised()
            ? "Name resolution is hidden, and Encrypted Client Hello was advertised, so some hostnames will show only an IP."
            : "Name resolution is not visible on the wire, so hostnames come only from TLS/QUIC SNI and may be incomplete.");

        ImGui::SameLine(ImGui::GetContentRegionMax().x - 70.0f);
        if (ImGui::SmallButton("Dismiss")) {
            m_dnsNoticeDismissed = true;
        }

        ImGui::EndChild();
        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);
        ImGui::Dummy(ImVec2(0, 4));
    }

} // namespace ui
