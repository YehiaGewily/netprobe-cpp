#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "core/ResourcePaths.hpp"
#include "imgui.h"
#include "implot.h"
#include <GLFW/glfw3.h>

#include <algorithm>
#include <array>
#include <filesystem>
#include <string>
#include <utility>
#include <vector>

namespace ui {

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

        const std::string throughput = formatFloat(m_currentMbps, 2);
        const std::string flows = formatCount(m_activeFlowCount);
        const std::string packets = formatCount(m_totalPackets);
        const std::string topApp = m_topService.empty() ? std::string{"--"} : m_topService;
        const std::string topAppSub = m_topService.empty()
            ? std::string{"awaiting traffic"}
            : (std::to_string(m_topServiceCount) + " packets");

        const std::array<Tile, 4> tiles = {{
            {"PACKETS",      packets,    "captured this session"},
            {"THROUGHPUT",   throughput + " MB/s", "peak " + formatFloat(m_peakMbps, 2) + " MB/s"},
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

    // First-run hero shown until the first packet arrives: tells the user how
    // to get traffic on screen instead of presenting empty charts and tables.
    void GuiLayer::renderEmptyState() {
        const auto textCentered = [](const std::string& text, const ImVec4& color) {
            const float w = ImGui::CalcTextSize(text.c_str()).x;
            ImGui::SetCursorPosX(std::max(0.0f, (ImGui::GetWindowSize().x - w) * 0.5f));
            ImGui::TextColored(color, "%s", text.c_str());
        };

        ImGui::Dummy(ImVec2(0, ImGui::GetContentRegionAvail().y * 0.24f));

        if (m_fontHeadline) ImGui::PushFont(m_fontHeadline);
        textCentered("Waiting for traffic", kText1);
        if (m_fontHeadline) ImGui::PopFont();
        ImGui::Dummy(ImVec2(0, 4));

        if (m_captureActive) {
            textCentered(m_devices.empty()
                ? "Capture is running."
                : ("Listening on " + m_devices[m_selectedDeviceIndex].displayLabel() + "."),
                kText2);
            textCentered("If nothing appears, live capture may need elevated privileges.", kText3);
        } else {
            textCentered("Live capture is stopped. Press Start in the toolbar to begin.", kText2);
        }
        ImGui::Dummy(ImVec2(0, 6));
        textCentered("You can also drop a .pcap / .pcapng file anywhere in this window.", kText3);
        ImGui::Dummy(ImVec2(0, 14));

        // Centered action buttons. The sample path resolves against the
        // running executable, not the CWD, so the button works when the app
        // is launched by double-click or from a macOS .app bundle.
        const auto samplePath = core::resource("data/sample.pcap");
        const bool sampleAvailable = std::filesystem::exists(samplePath);
        const float openW = 130.0f;
        const float sampleW = sampleAvailable ? 180.0f : 0.0f;
        const float totalW = openW + (sampleAvailable ? sampleW + 10.0f : 0.0f);
        ImGui::SetCursorPosX(std::max(0.0f, (ImGui::GetWindowSize().x - totalW) * 0.5f));
        ImGui::BeginDisabled(!m_nfdInitialized);
        if (ImGui::Button("Open PCAP...", ImVec2(openW, 0))) {
            openPcapDialog();
        }
        ImGui::EndDisabled();
        if (sampleAvailable) {
            ImGui::SameLine(0.0f, 10.0f);
            if (ImGui::Button("Open bundled sample", ImVec2(sampleW, 0))) {
                openPcapFile(samplePath.string());
            }
        }
    }

    void GuiLayer::renderCharts() {
        ImGui::Begin("Dashboard");

        if (m_totalPackets == 0) {
            renderEmptyState();
            ImGui::End();
            return;
        }

        renderKpiStrip();
        ImGui::Dummy(ImVec2(0, 8));

        // Bandwidth chart — minimal axes, filled total, TCP/UDP overlay lines.
        ImGui::PushStyleColor(ImGuiCol_ChildBg, kBgSurface);
        ImGui::PushStyleColor(ImGuiCol_Border, kBorderSoft);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 16));

        const float chartHostH = 260.0f;
        if (ImGui::BeginChild("##bandwidthHost", ImVec2(0, chartHostH), true,
                ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse)) {
            ImGui::TextColored(kText3, "BANDWIDTH");
            ImGui::SameLine();
            ImGui::TextColored(kText3, " — last 60 seconds");

            const std::string currentLabel = formatFloat(m_currentMbps, 2) + " MB/s";
            const float labelWidth = ImGui::CalcTextSize(currentLabel.c_str()).x;
            ImGui::SameLine(ImGui::GetContentRegionAvail().x - labelWidth + ImGui::GetCursorPosX() - ImGui::GetStyle().ItemSpacing.x);
            ImGui::TextColored(kText1, "%s", currentLabel.c_str());

            ImGui::Dummy(ImVec2(0, 4));

            if (ImPlot::BeginPlot("##bandwidth", ImVec2(-1, -1),
                    ImPlotFlags_NoTitle | ImPlotFlags_NoMouseText |
                    ImPlotFlags_NoBoxSelect | ImPlotFlags_NoFrame)) {
                ImPlot::SetupAxes(nullptr, nullptr,
                    ImPlotAxisFlags_NoLabel | ImPlotAxisFlags_NoTickLabels | ImPlotAxisFlags_NoTickMarks | ImPlotAxisFlags_AutoFit,
                    ImPlotAxisFlags_NoLabel | ImPlotAxisFlags_NoTickMarks | ImPlotAxisFlags_AutoFit);
                ImPlot::SetupAxisLimits(ImAxis_X1, glfwGetTime() - 60.0, glfwGetTime(), ImGuiCond_Always);
                ImPlot::SetupLegend(ImPlotLocation_NorthEast, ImPlotLegendFlags_NoButtons);

                linearizeBuffer(m_bandwidthData, m_scratchTime, m_scratchData);
                if (!m_scratchData.empty()) {
                    ImPlot::PlotShaded("Total",
                        m_scratchTime.data(), m_scratchData.data(),
                        static_cast<int>(m_scratchData.size()), 0.0,
                        ImPlotSpec(ImPlotProp_FillColor, kAccent,
                                   ImPlotProp_FillAlpha, 0.18f));
                    ImPlot::PlotLine("Total",
                        m_scratchTime.data(), m_scratchData.data(),
                        static_cast<int>(m_scratchData.size()),
                        ImPlotSpec(ImPlotProp_LineColor, kAccent,
                                   ImPlotProp_LineWeight, 1.75f));
                }
                linearizeBuffer(m_tcpBandwidth, m_scratchTime, m_scratchData);
                if (!m_scratchData.empty()) {
                    ImPlot::PlotLine("TCP",
                        m_scratchTime.data(), m_scratchData.data(),
                        static_cast<int>(m_scratchData.size()),
                        ImPlotSpec(ImPlotProp_LineColor, protocolColor("TCP"),
                                   ImPlotProp_LineWeight, 1.25f));
                }
                linearizeBuffer(m_udpBandwidth, m_scratchTime, m_scratchData);
                if (!m_scratchData.empty()) {
                    ImPlot::PlotLine("UDP",
                        m_scratchTime.data(), m_scratchData.data(),
                        static_cast<int>(m_scratchData.size()),
                        ImPlotSpec(ImPlotProp_LineColor, protocolColor("UDP"),
                                   ImPlotProp_LineWeight, 1.25f));
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
