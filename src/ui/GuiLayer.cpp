#include "ui/GuiLayer.hpp"
#include "core/ProtocolParser.hpp"
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include "implot.h"
#include <GLFW/glfw3.h>
#include <iostream>
#include <format>
#include <algorithm>

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
    }

    bool GuiLayer::init() {
        if (!glfwInit()) return false;

        const char* glsl_version = "#version 130";
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

        m_window = glfwCreateWindow(1280, 720, "NetProbe - C++20 Network Analyzer", NULL, NULL);
        if (!m_window) return false;

        glfwMakeContextCurrent(m_window);
        glfwSwapInterval(1); // Enable vsync

        IMGUI_CHECKVERSION();
        ImGui::CreateContext();
        ImPlot::CreateContext();
        
        ImGuiIO& io = ImGui::GetIO();
        io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
        io.ConfigFlags |= ImGuiConfigFlags_DockingEnable; 

        ImGui::StyleColorsDark();

        ImGui_ImplGlfw_InitForOpenGL(m_window, true);
        ImGui_ImplOpenGL3_Init(glsl_version);

        return true;
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
            glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

            glfwSwapBuffers(m_window);
        }
    }

    void GuiLayer::processQueue() {
        // Process up to 1000 packets per frame to maintain responsiveness
        int count = 0;
        double currentTime = glfwGetTime();

        while (count < 1000) {
            auto packetOpt = m_queue.try_pop();
            if (!packetOpt) break;

            auto parsed = core::ProtocolParser::parse(*packetOpt);
            
            // Add to history (limit to 10000 items)
            if (m_packetHistory.size() > 10000) m_packetHistory.pop_front();
            m_packetHistory.push_back(parsed);

            // Update Statistics
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
            m_bytesThisSec = 0;
            m_lastUpdateTime = currentTime;
        }
    }

    void GuiLayer::renderUI() {
        // Create a DockSpace
        ImGui::DockSpaceOverViewport(ImGui::GetMainViewport());

        renderMenuBar();
        renderPacketTable();
        renderCharts();
    }

    void GuiLayer::renderMenuBar() {
        if (ImGui::BeginMainMenuBar()) {
            if (ImGui::BeginMenu("File")) {
                if (ImGui::MenuItem("Exit")) glfwSetWindowShouldClose(m_window, true);
                ImGui::EndMenu();
            }
            ImGui::EndMainMenuBar();
        }
    }

    void GuiLayer::renderPacketTable() {
        ImGui::Begin("Live Packets");
        
        ImGui::Checkbox("Auto-scroll", &m_autoScroll);
        ImGui::SameLine();
        if (ImGui::Button("Clear")) {
            m_packetHistory.clear();
            m_appCounts.clear();
            m_bandwidthData.Erase();
        }

        if (ImGui::BeginTable("PacketTable", 6, 
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {
            
            ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 80.0f);
            ImGui::TableSetupColumn("Source IP", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Dest IP", ImGuiTableColumnFlags_WidthFixed, 100.0f);
            ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Service/Info", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            // Use cli-pper for performance
            ImGuiListClipper clipper;
            clipper.Begin((int)m_packetHistory.size());
            
            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    const auto& p = m_packetHistory[i];
                    ImGui::TableNextRow();
                    
                    ImGui::TableSetColumnIndex(0);
                    ImGui::Text("%lld", p.timestamp);
                    
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(p.srcIP.c_str());
                    
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(p.dstIP.c_str());
                    
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(p.protocol.c_str());
                    
                    ImGui::TableSetColumnIndex(4);
                    ImGui::Text("%d", p.length);
                    
                    ImGui::TableSetColumnIndex(5);
                    if (!p.service.empty()) {
                        ImGui::TextColored(ImVec4(0.4f, 1.0f, 0.4f, 1.0f), "[%s] %s", p.service.c_str(), p.sni.empty() ? "" : p.sni.c_str());
                    } else if (!p.sni.empty()) {
                        ImGui::Text("TLS: %s", p.sni.c_str());
                    } else if (p.dstPort == 443 || p.srcPort == 443) {
                        ImGui::TextDisabled("HTTPS (Encrypted)");
                    } else {
                        ImGui::TextDisabled("Raw");
                    }
                }
            }

            if (m_autoScroll && ImGui::GetScrollY() >= ImGui::GetScrollMaxY())
                ImGui::SetScrollHereY(1.0f);
            
            ImGui::EndTable();
        }
        ImGui::End();
    }

    void GuiLayer::renderCharts() {
        ImGui::Begin("Dashboard");

        // Top Apps Panel
        if (ImGui::CollapsingHeader("Top Applications", ImGuiTreeNodeFlags_DefaultOpen)) {
            if (m_appCounts.empty()) {
                ImGui::Text("No data identified yet.");
            } else {
                for (const auto& [name, count] : m_appCounts) {
                    ImGui::Text("%s: %d detected", name.c_str(), count);
                    ImGui::SameLine();
                    float fraction = (float)count / (float)m_packetHistory.size();
                    ImGui::ProgressBar(fraction, ImVec2(0.0f, 0.0f));
                }
            }
        }

        ImGui::Separator();

        // Bandwidth Chart
        if (ImPlot::BeginPlot("Total Bandwidth", ImVec2(-1, 0))) {
            ImPlot::SetupAxes("Time (s)", "Speed (MB/s)", ImPlotAxisFlags_AutoFit, ImPlotAxisFlags_AutoFit);
            ImPlot::SetupAxisLimits(ImAxis_X1, glfwGetTime() - 60.0, glfwGetTime(), ImGuiCond_Always);
            
            if (!m_bandwidthData.Data.empty()) {
                // Handle wrap-around for scrolling buffer
                // For simplicity here, we just plot the whole buffer incorrectly if wrapped, 
                // but the proper way is two plot calls or sorting.
                // However, ImPlot handles raw pointers.
                
                // Construct continuous arrays for display if needed or just plot directly
                // Given standard implementation of scrolling buffer with Offset:
                int offset = m_bandwidthData.Offset;
                // ImPlot::PlotLine("MB/s", m_bandwidthData.Time.data(), m_bandwidthData.Data.data(), m_bandwidthData.Data.size(), offset); 
                // Note: ImPlot API might vary slightly by version, checking usage
                // Standard ImPlot usage for ring buffer: data, count, offset, stride
                
                 ImPlot::PlotLine("MB/s", 
                    m_bandwidthData.Time.data(), 
                    m_bandwidthData.Data.data(), 
                    m_bandwidthData.Data.size(), 
                    offset // offset
                );
            }
            ImPlot::EndPlot();
        }

        ImGui::End();
    }

} // namespace ui
