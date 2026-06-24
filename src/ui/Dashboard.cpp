#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "imgui.h"
#include "implot.h"
#include <GLFW/glfw3.h>

#include <algorithm>
#include <array>
#include <format>
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
