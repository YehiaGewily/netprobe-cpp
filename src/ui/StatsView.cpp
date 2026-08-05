#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "core/FlowAggregator.hpp"
#include "imgui.h"

#include <algorithm>
#include <format>
#include <string>
#include <unordered_map>
#include <vector>

namespace ui {

    namespace {

        // Label + count + thin share bar, matching the Top Services list style.
        void shareRow(const std::string& name, const ImVec4& dotColor,
            const std::string& valueText, float fraction, const std::string& shareText) {
            const float nameCol = 150.0f;
            const float valueCol = 90.0f;
            const float pctCol = 60.0f;

            drawDot(dotColor);
            ImGui::SameLine();
            ImGui::TextColored(kText1, "%s", name.c_str());
            ImGui::SameLine(nameCol);

            const ImVec2 barP = ImGui::GetCursorScreenPos();
            const float barW = std::max(20.0f,
                ImGui::GetContentRegionAvail().x - valueCol - pctCol);
            const float barH = 6.0f;
            const float trackY = barP.y + ImGui::GetTextLineHeight() * 0.5f - barH * 0.5f;
            ImDrawList* dl = ImGui::GetWindowDrawList();
            dl->AddRectFilled(
                ImVec2(barP.x, trackY),
                ImVec2(barP.x + barW, trackY + barH),
                ImGui::GetColorU32(kBgInput), barH * 0.5f);
            dl->AddRectFilled(
                ImVec2(barP.x, trackY),
                ImVec2(barP.x + barW * std::clamp(fraction, 0.0f, 1.0f), trackY + barH),
                ImGui::GetColorU32(kAccent), barH * 0.5f);
            ImGui::Dummy(ImVec2(barW, ImGui::GetTextLineHeight()));

            ImGui::SameLine();
            ImGui::TextColored(kText1, "%s", valueText.c_str());
            ImGui::SameLine(ImGui::GetContentRegionAvail().x + ImGui::GetCursorPosX() - pctCol);
            ImGui::TextColored(kText3, "%s", shareText.c_str());
        }

    }

    void GuiLayer::renderStatsView() {
        ImGui::Begin("Statistics");

        ImGui::PushStyleColor(ImGuiCol_ChildBg, kBgSurface);
        ImGui::PushStyleColor(ImGuiCol_Border, kBorderSoft);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ChildBorderSize, 1.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(18, 16));

        const float spacing = 12.0f;
        const float colW = (ImGui::GetContentRegionAvail().x - spacing) * 0.5f;

        // --- Protocol breakdown -------------------------------------------
        if (ImGui::BeginChild("##protocolStats", ImVec2(colW, 0), true)) {
            // How hostnames are being resolved decides how much of the rest of
            // this view can be labelled at all, so it goes first.
            ImGui::TextColored(kText3, "NAME RESOLUTION");
            ImGui::Dummy(ImVec2(0, 4));
            const uint64_t plaintextDns = m_session.plaintextDnsResponses();
            const uint64_t encryptedDns = m_session.encryptedDnsPackets();
            if (plaintextDns == 0 && encryptedDns == 0) {
                ImGui::TextColored(kText3, "No DNS observed yet.");
            } else {
                ImGui::TextColored(kText2, "Plaintext DNS responses");
                ImGui::SameLine(220.0f);
                ImGui::TextColored(kText1, "%s", formatCount(plaintextDns).c_str());

                ImGui::TextColored(kText2, "Encrypted DNS sightings");
                ImGui::SameLine(220.0f);
                ImGui::TextColored(encryptedDns > 0 ? kWarning : kText1,
                    "%s", formatCount(encryptedDns).c_str());

                ImGui::TextColored(kText2, "Encrypted Client Hello");
                ImGui::SameLine(220.0f);
                if (m_session.echAdvertised()) {
                    ImGui::TextColored(kWarning, "advertised");
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
                        ImGui::SetTooltip(
                            "A DNS HTTPS record published an ECH config.\n"
                            "Clients honouring it encrypt the SNI, so those\n"
                            "connections show an IP instead of a hostname.");
                    }
                } else {
                    ImGui::TextColored(kText1, "not seen");
                }
            }

            ImGui::Dummy(ImVec2(0, 10));
            ImGui::Separator();
            ImGui::Dummy(ImVec2(0, 6));

            ImGui::TextColored(kText3, "PROTOCOLS");
            ImGui::Dummy(ImVec2(0, 6));

            if (m_protocolCounts.empty()) {
                ImGui::TextColored(kText3, "Protocol distribution will appear here once traffic is observed.");
            } else {
                std::vector<std::pair<std::string, uint64_t>> sorted(
                    m_protocolCounts.begin(), m_protocolCounts.end());
                std::sort(sorted.begin(), sorted.end(),
                    [](const auto& a, const auto& b) { return a.second > b.second; });

                const uint64_t maxCount = sorted.front().second;
                for (const auto& [name, count] : sorted) {
                    const float fraction = maxCount == 0
                        ? 0.0f
                        : static_cast<float>(count) / static_cast<float>(maxCount);
                    const float share = m_totalPackets == 0
                        ? 0.0f
                        : static_cast<float>(count) / static_cast<float>(m_totalPackets);
                    const uint64_t bytes = m_protocolBytes.contains(name)
                        ? m_protocolBytes.at(name) : 0;
                    shareRow(name, protocolColor(name),
                        std::format("{}  {}", formatCount(count), formatBytes(bytes)),
                        fraction, std::format("{:.1f}%", share * 100.0f));
                }
            }
        }
        ImGui::EndChild();

        ImGui::SameLine(0.0f, spacing);

        // --- Top talkers ----------------------------------------------------
        if (ImGui::BeginChild("##topTalkers", ImVec2(0, 0), true)) {
            ImGui::TextColored(kText3, "TOP TALKERS");
            ImGui::SameLine();
            ImGui::TextColored(kText3, " — by bytes, per remote host");
            ImGui::Dummy(ImVec2(0, 6));

            struct Talker {
                std::string host;
                uint64_t bytes = 0;
                uint64_t packets = 0;
                int flows = 0;
            };
            // Reuses the flow snapshot cached by refreshFlowsCache (0.5s
            // cadence) instead of taking a second full snapshot every frame.
            refreshFlowsCache();
            std::unordered_map<std::string, Talker> byHost;
            uint64_t totalBytes = 0;
            for (const auto& flow : m_flowsCache) {
                const std::string& host = flow.hostname.empty() ? flow.key.dstIP : flow.hostname;
                Talker& talker = byHost[host];
                talker.host = host;
                talker.bytes += flow.bytesUp + flow.bytesDown;
                talker.packets += flow.packets;
                talker.flows += 1;
                totalBytes += flow.bytesUp + flow.bytesDown;
            }

            if (byHost.empty()) {
                ImGui::TextColored(kText3, "Remote hosts will appear here once flows are observed.");
            } else {
                std::vector<Talker> talkers;
                talkers.reserve(byHost.size());
                for (auto& [_, talker] : byHost) talkers.push_back(std::move(talker));
                std::sort(talkers.begin(), talkers.end(),
                    [](const Talker& a, const Talker& b) { return a.bytes > b.bytes; });
                if (talkers.size() > 15) talkers.resize(15);

                const uint64_t maxBytes = talkers.front().bytes;
                for (const auto& talker : talkers) {
                    const float fraction = maxBytes == 0
                        ? 0.0f
                        : static_cast<float>(talker.bytes) / static_cast<float>(maxBytes);
                    const float share = totalBytes == 0
                        ? 0.0f
                        : static_cast<float>(talker.bytes) / static_cast<float>(totalBytes);
                    // Keep long hostnames inside the label column; the tooltip
                    // carries the full name.
                    const std::string label = talker.host.size() > 21
                        ? talker.host.substr(0, 20) + "…"
                        : talker.host;
                    shareRow(label, serviceColor(talker.host),
                        std::format("{}  ({} flows)", formatBytes(talker.bytes), talker.flows),
                        fraction, std::format("{:.1f}%", share * 100.0f));
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
                        ImGui::SetTooltip("%s\n%s in %d flow(s), %s packets",
                            talker.host.c_str(), formatBytes(talker.bytes).c_str(),
                            talker.flows, formatCount(talker.packets).c_str());
                    }
                }
            }
        }
        ImGui::EndChild();

        ImGui::PopStyleVar(3);
        ImGui::PopStyleColor(2);

        ImGui::End();
    }

} // namespace ui
