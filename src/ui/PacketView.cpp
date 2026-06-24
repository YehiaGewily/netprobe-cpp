#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "core/FlowAggregator.hpp"
#include "imgui.h"

#include <chrono>
#include <format>
#include <vector>

namespace ui {

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

        if (ImGui::BeginTable("PacketTable", 7,
            ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {

            ImGui::TableSetupColumn("Time", ImGuiTableColumnFlags_WidthFixed, 105.0f);
            ImGui::TableSetupColumn("Source IP", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("Dest IP", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("Length", ImGuiTableColumnFlags_WidthFixed, 60.0f);
            ImGui::TableSetupColumn("App", ImGuiTableColumnFlags_WidthFixed, 140.0f);
            ImGui::TableSetupColumn("Service / Info", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableHeadersRow();

            std::vector<size_t> matchingPacketIndexes;
            if (m_packetFlowFilter) {
                matchingPacketIndexes.reserve(m_packetHistory.size());
                for (size_t index = 0; index < m_packetHistory.size(); ++index) {
                    if (core::FlowAggregator::matches(m_packetHistory[index].parsed, *m_packetFlowFilter)) {
                        matchingPacketIndexes.push_back(index);
                    }
                }
            }

            const int rowCount = m_packetFlowFilter
                ? static_cast<int>(matchingPacketIndexes.size())
                : static_cast<int>(m_packetHistory.size());

            ImGuiListClipper clipper;
            clipper.Begin(rowCount);

            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    const size_t packetIndex = m_packetFlowFilter
                        ? matchingPacketIndexes[static_cast<size_t>(i)]
                        : static_cast<size_t>(i);
                    const auto& p = m_packetHistory[packetIndex].parsed;
                    ImGui::TableNextRow();

                    // Make the time cell drive row selection. Span-all-columns
                    // would conflict with the per-cell coloring we want below,
                    // so we treat the first column as the click target and
                    // visually mark the selected row via TableSetBgColor.
                    ImGui::TableSetColumnIndex(0);
                    const bool selected = (static_cast<int>(packetIndex) == m_selectedPacketIndex);
                    const auto timestamp = std::chrono::sys_time<std::chrono::microseconds>{
                        std::chrono::microseconds{p.timestamp}
                    };
                    const auto seconds = std::chrono::floor<std::chrono::seconds>(timestamp);
                    const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp - seconds).count();
                    const auto timeText = std::format("{:%H:%M:%S}.{:03}", seconds, milliseconds);
                    ImGui::PushID(static_cast<int>(packetIndex));
                    if (ImGui::Selectable(timeText.c_str(), selected,
                            ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                        m_selectedPacketIndex = static_cast<int>(packetIndex);
                    }
                    ImGui::PopID();
                    if (selected) {
                        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                            ImGui::GetColorU32(kAccentSoft));
                    }

                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(p.srcIP.c_str());

                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(p.dstIP.c_str());

                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextColored(protocolColor(p.protocol), "%s", p.protocol.c_str());

                    ImGui::TableSetColumnIndex(4);
                    ImGui::Text("%u", p.length);

                    ImGui::TableSetColumnIndex(5);
                    if (const std::string app = m_processResolver.lookup(p); !app.empty()) {
                        ImGui::TextColored(kText1, "%s", app.c_str());
                    } else {
                        ImGui::TextDisabled("--");
                    }

                    ImGui::TableSetColumnIndex(6);
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

} // namespace ui
