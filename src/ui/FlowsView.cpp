#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "core/FlowAggregator.hpp"
#include "core/GeoIPResolver.hpp"
#include "imgui.h"

#include <algorithm>
#include <format>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace ui {

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

} // namespace ui
