#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "core/FlowAggregator.hpp"
#include "imgui.h"

#include <cctype>
#include <chrono>
#include <format>
#include <string>
#include <vector>

namespace ui {

    namespace {

        // Case-insensitive substring search; the needle is already lowercase.
        bool containsCI(const std::string& haystack, const std::string& needleLower) {
            if (needleLower.empty()) return true;
            if (haystack.size() < needleLower.size()) return false;
            for (size_t i = 0; i + needleLower.size() <= haystack.size(); ++i) {
                size_t j = 0;
                while (j < needleLower.size()
                    && std::tolower(static_cast<unsigned char>(haystack[i + j])) == needleLower[j]) {
                    ++j;
                }
                if (j == needleLower.size()) return true;
            }
            return false;
        }

        std::string formatPacketTime(int64_t micros) {
            const auto timestamp = std::chrono::sys_time<std::chrono::microseconds>{
                std::chrono::microseconds{micros}
            };
            const auto seconds = std::chrono::floor<std::chrono::seconds>(timestamp);
            const auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp - seconds).count();
            return std::format("{:%H:%M:%S}.{:03}", seconds, milliseconds);
        }

    }

    bool GuiLayer::packetMatchesDisplayFilter(const core::ParsedPacket& packet) const {
        if (m_displayFilter[0] == '\0') return true;
        std::string needle{m_displayFilter};
        for (char& c : needle) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (containsCI(packet.srcIP, needle)) return true;
        if (containsCI(packet.dstIP, needle)) return true;
        if (containsCI(packet.protocol, needle)) return true;
        if (containsCI(packet.service, needle)) return true;
        if (containsCI(packet.sni, needle)) return true;
        if (containsCI(packet.hostname, needle)) return true;
        if (containsCI(packet.info, needle)) return true;
        if (containsCI(packet.tunnel, needle)) return true;
        if (packet.srcPort != 0 && containsCI(std::format("{}", packet.srcPort), needle)) return true;
        if (packet.dstPort != 0 && containsCI(std::format("{}", packet.dstPort), needle)) return true;
        if (const auto hostname = m_hostnameCache.lookup(packet.dstIP);
            hostname && containsCI(*hostname, needle)) return true;
        return false;
    }

    void GuiLayer::renderPacketTable() {
        ImGui::Begin("Live Packets");

        // Toolbar: display filter + view controls. The display filter narrows
        // what is shown; it never affects capture (that's the BPF box above).
        ImGui::SetNextItemWidth(220.0f);
        if (m_focusDisplayFilter) {
            ImGui::SetKeyboardFocusHere();
            m_focusDisplayFilter = false;
        }
        ImGui::InputTextWithHint("##displayFilter", "Search shown packets (/)",
            m_displayFilter, sizeof(m_displayFilter));
        ImGui::SetItemTooltip("Filter displayed packets by IP, hostname, protocol,\nservice, SNI, or port. Press / to focus.");
        if (m_displayFilter[0] != '\0') {
            ImGui::SameLine(0.0f, 4.0f);
            if (ImGui::SmallButton("x##clearDisplayFilter")) {
                m_displayFilter[0] = '\0';
            }
        }

        ImGui::SameLine();
        ImGui::Checkbox("Auto-scroll", &m_autoScroll);
        if (!m_autoScroll) {
            ImGui::SameLine();
            if (ImGui::SmallButton("Jump to latest")) {
                m_autoScroll = true;
            }
        }
        ImGui::SameLine();
        if (ImGui::Button("Clear capture")) {
            clearCaptureView();
        }

        if (m_packetFlowFilter) {
            ImGui::SameLine();
            ImGui::TextDisabled("|");
            ImGui::SameLine();
            ImGui::TextColored(kAccent, "Flow: %s:%u",
                m_packetFlowFilter->dstIP.c_str(), m_packetFlowFilter->dstPort);
            ImGui::SameLine();
            if (ImGui::SmallButton("Clear##flowFilter")) {
                m_packetFlowFilter.reset();
            }
        }

        // Resolve the visible row set once per frame.
        const bool displayFilterActive = m_displayFilter[0] != '\0';
        const bool anyFilter = m_packetFlowFilter.has_value() || displayFilterActive;
        std::vector<size_t> matchingPacketIndexes;
        if (anyFilter) {
            matchingPacketIndexes.reserve(m_packetHistory.size());
            for (size_t index = 0; index < m_packetHistory.size(); ++index) {
                const auto& parsed = m_packetHistory[index].parsed;
                if (m_packetFlowFilter
                    && !core::FlowAggregator::matches(parsed, *m_packetFlowFilter)) {
                    continue;
                }
                if (displayFilterActive && !packetMatchesDisplayFilter(parsed)) {
                    continue;
                }
                matchingPacketIndexes.push_back(index);
            }
        }
        const int rowCount = anyFilter
            ? static_cast<int>(matchingPacketIndexes.size())
            : static_cast<int>(m_packetHistory.size());

        ImGui::SameLine();
        if (anyFilter) {
            ImGui::TextDisabled("%d / %zu packets", rowCount, m_packetHistory.size());
        } else {
            ImGui::TextDisabled("%zu packets shown", m_packetHistory.size());
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

            ImGuiListClipper clipper;
            clipper.Begin(rowCount);

            while (clipper.Step()) {
                for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; i++) {
                    const size_t packetIndex = anyFilter
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
                    const auto timeText = formatPacketTime(p.timestamp);
                    ImGui::PushID(static_cast<int>(packetIndex));
                    if (ImGui::Selectable(timeText.c_str(), selected,
                            ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                        m_selectedPacketIndex = static_cast<int>(packetIndex);
                        // Inspecting a packet while rows stream past is
                        // hopeless — implicitly hold the view still.
                        m_autoScroll = false;
                    }
                    if (ImGui::BeginPopupContextItem("##packetContext")) {
                        if (ImGui::MenuItem("Copy row")) {
                            const std::string row = std::format(
                                "{}\t{}:{}\t{}:{}\t{}\t{}\t{}\t{}",
                                timeText, p.srcIP, p.srcPort, p.dstIP, p.dstPort,
                                p.protocol, p.length, p.service, p.sni);
                            ImGui::SetClipboardText(row.c_str());
                        }
                        if (ImGui::MenuItem("Copy source IP")) {
                            ImGui::SetClipboardText(p.srcIP.c_str());
                        }
                        if (ImGui::MenuItem("Copy dest IP")) {
                            ImGui::SetClipboardText(p.dstIP.c_str());
                        }
                        ImGui::Separator();
                        if (const auto key = core::FlowAggregator::keyFor(p)) {
                            if (ImGui::MenuItem("Filter by this flow")) {
                                m_packetFlowFilter = *key;
                            }
                        }
                        if (m_packetFlowFilter && ImGui::MenuItem("Clear flow filter")) {
                            m_packetFlowFilter.reset();
                        }
                        ImGui::EndPopup();
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
                    // Encapsulated packets get a leading badge so the tunnel is
                    // never mistaken for the real conversation.
                    if (!p.tunnel.empty()) {
                        ImGui::TextColored(kWarning, "[%s]", p.tunnel.c_str());
                        ImGui::SameLine();
                    }
                    if (!p.service.empty()) {
                        drawDot(serviceColor(p.service));
                        ImGui::SameLine();
                        ImGui::TextColored(kText1, "%s", p.service.c_str());
                        const std::string& detail = !p.sni.empty() ? p.sni
                                                  : !p.hostname.empty() ? p.hostname
                                                  : p.info;
                        if (!detail.empty()) {
                            ImGui::SameLine();
                            ImGui::TextColored(kText3, "%s", detail.c_str());
                        }
                    } else if (!p.sni.empty()) {
                        ImGui::TextColored(kText3, "TLS");
                        ImGui::SameLine();
                        ImGui::TextColored(kText2, "%s", p.sni.c_str());
                    } else if (!p.info.empty()) {
                        ImGui::TextColored(kText2, "%s", p.info.c_str());
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
