#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "core/FlowAggregator.hpp"
#include "core/FlowExporter.hpp"
#include "core/GeoIPResolver.hpp"
#include "imgui.h"
#include "implot.h"
#include <GLFW/glfw3.h>

#include <algorithm>
#include <fstream>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

namespace ui {

    namespace {

        using core::organizationLabel;

        uint64_t retransmissionsOf(const core::Flow& flow) {
            return flow.retransmissionsUp + flow.retransmissionsDown;
        }

        uint64_t outOfOrderOf(const core::Flow& flow) {
            return flow.outOfOrderUp + flow.outOfOrderDown;
        }

        // Retransmissions as a share of the flow's packets. A rate reads
        // better than a raw count: 20 retransmits out of 50 packets is a
        // broken connection, out of 500,000 it is noise.
        //
        // Reordering is deliberately kept out of this number. The two have
        // different causes — loss versus multipath or queueing — and merging
        // them produces a figure that cannot be acted on. Out-of-order counts
        // live in the tooltip and the detail pane.
        double retransmissionRateOf(const core::Flow& flow) {
            if (flow.packets == 0) return 0.0;
            return 100.0 * static_cast<double>(retransmissionsOf(flow))
                / static_cast<double>(flow.packets);
        }

        // Two-column key/value row used by the flow detail pane.
        void detailRow(const char* key, const std::string& value) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextColored(kText3, "%s", key);
            ImGui::TableSetColumnIndex(1);
            if (value.empty() || value == "-") {
                ImGui::TextDisabled("--");
            } else {
                ImGui::TextColored(kText1, "%s", value.c_str());
                if (ImGui::CalcTextSize(value.c_str()).x > ImGui::GetContentRegionAvail().x) {
                    ImGui::SetItemTooltip("%s", value.c_str());
                }
            }
        }

    }

    bool GuiLayer::exportFlowsCsv(const std::string& path, std::string& error) {
        return core::FlowExporter::writeCsv(m_session.flows(currentUnixTimeMicroseconds()),
            path, error, &m_geoIPResolver);
    }

    // Refresh the shared flow snapshot on a 0.5s cadence. Copying every flow,
    // resolving GeoIP, and sorting were previously done per frame in both the
    // Flows and Statistics views; at high flow counts that dominated the frame.
    void GuiLayer::refreshFlowsCache() {
        const double now = glfwGetTime();
        if (m_lastFlowsRefresh >= 0.0 && now - m_lastFlowsRefresh < 0.5) return;
        m_lastFlowsRefresh = now;

        m_flowsCache = m_session.flows(currentUnixTimeMicroseconds());
        m_activeFlowCount = m_flowsCache.size();

        // The geo cache persists across refreshes so each destination IP is
        // resolved once; keep it from growing without bound on long captures.
        if (m_flowGeoCache.size() > 8192) m_flowGeoCache.clear();
        m_maxFlowBytes = 0;
        for (const auto& flow : m_flowsCache) {
            if (!m_flowGeoCache.contains(flow.key.dstIP)) {
                m_flowGeoCache.emplace(flow.key.dstIP, m_geoIPResolver.lookup(flow.key.dstIP));
            }
            m_maxFlowBytes = std::max<uint64_t>(m_maxFlowBytes, flow.bytesUp + flow.bytesDown);
        }
        m_flowSortDirty = true;
    }

    void GuiLayer::sortFlowsCache() {
        m_flowSortDirty = false;
        static const core::GeoIPInfo kNoGeo{};
        const auto geoFor = [this](const std::string& ip) -> const core::GeoIPInfo& {
            const auto it = m_flowGeoCache.find(ip);
            return it == m_flowGeoCache.end() ? kNoGeo : it->second;
        };
        const auto compareFlows = [this, &geoFor](const core::Flow& left, const core::Flow& right) {
            const std::string& leftHost = left.hostname.empty() ? left.key.dstIP : left.hostname;
            const std::string& rightHost = right.hostname.empty() ? right.key.dstIP : right.hostname;
            const auto& leftGeo = geoFor(left.key.dstIP);
            const auto& rightGeo = geoFor(right.key.dstIP);
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
            case 8: {
                // Unknown RTT (0) sorts to the bottom regardless of direction
                // so flows with measurements always cluster at the top.
                const int64_t lr = left.initialRttMicroseconds == 0 ? INT64_MAX : left.initialRttMicroseconds;
                const int64_t rr = right.initialRttMicroseconds == 0 ? INT64_MAX : right.initialRttMicroseconds;
                comparison = lr < rr ? -1 : lr > rr ? 1 : 0;
                break;
            }
            case 9: {
                const double leftRate = retransmissionRateOf(left);
                const double rightRate = retransmissionRateOf(right);
                comparison = leftRate < rightRate ? -1 : leftRate > rightRate ? 1 : 0;
                break;
            }
            case 10: comparison = (left.lastSeen - left.firstSeen) < (right.lastSeen - right.firstSeen) ? -1
                : (left.lastSeen - left.firstSeen) > (right.lastSeen - right.firstSeen) ? 1 : 0; break;
            case 11: comparison = left.process.compare(right.process); break;
            default: break;
            }
            if (comparison == 0) comparison = leftHost.compare(rightHost);
            return m_flowSortAscending ? comparison < 0 : comparison > 0;
        };
        std::sort(m_flowsCache.begin(), m_flowsCache.end(), compareFlows);
    }

    void GuiLayer::renderFlowDetail(const core::Flow& flow, const core::GeoIPInfo& geo) {
        const std::string& host = flow.hostname.empty() ? flow.key.dstIP : flow.hostname;

        if (m_fontBrand) ImGui::PushFont(m_fontBrand);
        ImGui::TextColored(kText1, "%s", host.c_str());
        if (m_fontBrand) ImGui::PopFont();
        if (!flow.service.empty()) {
            ImGui::SameLine();
            drawDot(serviceColor(flow.service));
            ImGui::SameLine();
            ImGui::TextColored(kText2, "%s", flow.service.c_str());
        }
        if (ImGui::SmallButton("Show packets")) {
            // The selection already filters Live Packets; this is a discoverable
            // affordance that just focuses that window.
            ImGui::SetWindowFocus("Live Packets");
        }
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear selection")) {
            m_packetFlowFilter.reset();
            return;
        }
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        constexpr ImGuiTableFlags kFieldFlags =
            ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoBordersInBody;
        if (ImGui::BeginTable("FlowDetailFields", 2, kFieldFlags)) {
            ImGui::TableSetupColumn("##key", ImGuiTableColumnFlags_WidthFixed, 78.0f);
            ImGui::TableSetupColumn("##value", ImGuiTableColumnFlags_WidthStretch);

            detailRow("Endpoints", (flow.key.srcIP + ":" + std::to_string(flow.key.srcPort) +
                "  ->  " + flow.key.dstIP + ":" + std::to_string(flow.key.dstPort)).c_str());
            detailRow("Protocol", flow.key.protocol);
            detailRow("Process", flow.process);
            detailRow("Country", geo.country.empty() ? "-" : geo.country);
            detailRow("Org", organizationLabel(geo));
            // Name the direction by its endpoint rather than "up"/"down": for a
            // peer-to-peer flow neither side is the client.
            detailRow((flow.key.srcIP + " sent").c_str(), formatBytes(flow.bytesUp));
            detailRow((flow.key.dstIP + " sent").c_str(), formatBytes(flow.bytesDown));
            detailRow("Packets", std::to_string(flow.packets));
            detailRow("Rate", formatBytes(static_cast<uint64_t>(flow.rateBytesPerSecond)) + "/s");
            if (flow.initialRttMicroseconds > 0) {
                detailRow("Init RTT", formatFloat(static_cast<double>(flow.initialRttMicroseconds) / 1000.0, 1) + " ms");
            } else {
                detailRow("Init RTT", "");
            }
            detailRow("Duration", formatDuration(flow.firstSeen, flow.lastSeen));
            if (flow.key.protocol == "TCP") {
                // Per direction and absolute here: the table already shows the
                // combined rate, and when diagnosing you need to know which
                // side is losing packets.
                detailRow("Retrans", std::to_string(flow.retransmissionsUp) + " / " +
                    std::to_string(flow.retransmissionsDown));
                detailRow("Reordered", std::to_string(flow.outOfOrderUp) + " / " +
                    std::to_string(flow.outOfOrderDown));
            }

            ImGui::EndTable();
        }

        if (flow.encryptedTunnel) {
            ImGui::Spacing();
            ImGui::TextColored(kWarning, "Encrypted tunnel");
            ImGui::TextWrapped(
                "This flow carries other traffic inside it. NetProbe can measure "
                "the tunnel but cannot see the conversations within.");
        }

        ImGui::Spacing();
        ImGui::TextColored(kText3, "RATE — last 2 minutes");
        if (ImPlot::BeginPlot("##flowRate", ImVec2(-1, 110),
                ImPlotFlags_NoTitle | ImPlotFlags_NoMouseText | ImPlotFlags_NoLegend |
                ImPlotFlags_NoBoxSelect | ImPlotFlags_NoFrame)) {
            ImPlot::SetupAxes(nullptr, nullptr,
                ImPlotAxisFlags_NoLabel | ImPlotAxisFlags_NoTickLabels | ImPlotAxisFlags_NoTickMarks,
                ImPlotAxisFlags_NoLabel | ImPlotAxisFlags_NoTickLabels | ImPlotAxisFlags_NoTickMarks | ImPlotAxisFlags_AutoFit);
            ImPlot::SetupAxisLimits(ImAxis_X1, glfwGetTime() - 120.0, glfwGetTime(), ImGuiCond_Always);
            linearizeBuffer(m_flowRateHistory, m_scratchTime, m_scratchData);
            if (!m_scratchData.empty()) {
                ImPlot::PlotShaded("B/s",
                    m_scratchTime.data(), m_scratchData.data(),
                    static_cast<int>(m_scratchData.size()), 0.0,
                    ImPlotSpec(ImPlotProp_FillColor, kAccent,
                               ImPlotProp_FillAlpha, 0.18f));
                ImPlot::PlotLine("B/s",
                    m_scratchTime.data(), m_scratchData.data(),
                    static_cast<int>(m_scratchData.size()),
                    ImPlotSpec(ImPlotProp_LineColor, kAccent,
                               ImPlotProp_LineWeight, 1.5f));
            }
            ImPlot::EndPlot();
        }
    }

    void GuiLayer::renderFlowsTable() {
        ImGui::Begin("Flows");

        refreshFlowsCache();
        static const core::GeoIPInfo kNoGeo{};
        const auto geoFor = [this](const std::string& ip) -> const core::GeoIPInfo& {
            const auto it = m_flowGeoCache.find(ip);
            return it == m_flowGeoCache.end() ? kNoGeo : it->second;
        };

        // Locate the selected flow (if any) and keep its rate history sampled
        // so the detail pane can draw a sparkline. Copied by value because the
        // cached flows vector may be re-sorted below.
        std::optional<core::Flow> selectedFlow;
        if (m_packetFlowFilter) {
            for (const auto& flow : m_flowsCache) {
                if (flow.key == *m_packetFlowFilter) { selectedFlow = flow; break; }
            }
        }
        if (selectedFlow) {
            if (!m_flowRateKey || !(*m_flowRateKey == selectedFlow->key)) {
                m_flowRateKey = selectedFlow->key;
                m_flowRateHistory.Erase();
                m_lastFlowSampleTime = 0.0;
            }
            const double now = glfwGetTime();
            if (now - m_lastFlowSampleTime >= 0.5) {
                m_flowRateHistory.AddPoint(static_cast<float>(now),
                    static_cast<float>(selectedFlow->rateBytesPerSecond));
                m_lastFlowSampleTime = now;
            }
        } else if (m_flowRateKey) {
            m_flowRateKey.reset();
            m_flowRateHistory.Erase();
        }

        // When a flow is selected the window splits: table left, detail right.
        const float detailWidth = scaled(330.0f);
        const bool showDetail = selectedFlow.has_value()
            && ImGui::GetContentRegionAvail().x > detailWidth + scaled(260.0f);
        if (showDetail) {
            ImGui::BeginChild("##flowTableHost",
                ImVec2(ImGui::GetContentRegionAvail().x - detailWidth - 8.0f, 0), false);
        }

        constexpr ImGuiTableFlags tableFlags = ImGuiTableFlags_ScrollY
            | ImGuiTableFlags_RowBg
            | ImGuiTableFlags_Borders
            | ImGuiTableFlags_Resizable
            | ImGuiTableFlags_Sortable;

        if (ImGui::BeginTable("FlowsTable", 12, tableFlags)) {
            ImGui::TableSetupColumn("Host", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Country", ImGuiTableColumnFlags_WidthFixed, scaled(65.0f));
            ImGui::TableSetupColumn("Org", ImGuiTableColumnFlags_WidthFixed, scaled(180.0f));
            ImGui::TableSetupColumn("Service", ImGuiTableColumnFlags_WidthFixed, scaled(100.0f));
            ImGui::TableSetupColumn("Proto", ImGuiTableColumnFlags_WidthFixed, scaled(100.0f));
            ImGui::TableSetupColumn("Pkts", ImGuiTableColumnFlags_WidthFixed, scaled(65.0f));
            ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, scaled(90.0f));
            ImGui::TableSetupColumn("Rate", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending, scaled(90.0f));
            ImGui::TableSetupColumn("RTT", ImGuiTableColumnFlags_WidthFixed, scaled(85.0f));
            ImGui::TableSetupColumn("Retrans", ImGuiTableColumnFlags_WidthFixed | ImGuiTableColumnFlags_PreferSortDescending, scaled(78.0f));
            ImGui::TableSetupColumn("Dur", ImGuiTableColumnFlags_WidthFixed, scaled(70.0f));
            ImGui::TableSetupColumn("App", ImGuiTableColumnFlags_WidthFixed, scaled(130.0f));
            ImGui::TableHeadersRow();

            if (ImGuiTableSortSpecs* sortSpecs = ImGui::TableGetSortSpecs(); sortSpecs && sortSpecs->SpecsDirty) {
                m_flowSortColumn = sortSpecs->Specs[0].ColumnIndex;
                m_flowSortAscending = sortSpecs->Specs[0].SortDirection == ImGuiSortDirection_Ascending;
                sortSpecs->SpecsDirty = false;
                m_flowSortDirty = true;
            }
            if (m_flowSortDirty) sortFlowsCache();

            ImGuiListClipper clipper;
            clipper.Begin(static_cast<int>(m_flowsCache.size()));
            while (clipper.Step()) {
                for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                    const auto& flow = m_flowsCache[static_cast<size_t>(index)];
                    const std::string& host = flow.hostname.empty() ? flow.key.dstIP : flow.hostname;
                    const auto& geoInfo = geoFor(flow.key.dstIP);
                    const std::string country = geoInfo.country.empty() ? "-" : geoInfo.country;
                    const std::string organization = organizationLabel(geoInfo);
                    const uint64_t totalBytes = flow.bytesUp + flow.bytesDown;
                    const bool selected = m_packetFlowFilter && *m_packetFlowFilter == flow.key;

                    ImGui::PushID(index);
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    if (ImGui::Selectable(host.c_str(), selected,
                        ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowOverlap)) {
                        // Click toggles: selecting an already-selected flow clears it.
                        if (selected) {
                            m_packetFlowFilter.reset();
                        } else {
                            m_packetFlowFilter = flow.key;
                        }
                    }
                    if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
                        ImGui::SetTooltip("%s\n%s -> %s:%u", host.c_str(),
                            flow.key.srcIP.c_str(), flow.key.dstIP.c_str(), flow.key.dstPort);
                    }
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(country.c_str());
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(organization.c_str());
                    if (organization.size() > 24 && ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
                        ImGui::SetTooltip("%s", organization.c_str());
                    }
                    ImGui::TableSetColumnIndex(3);
                    if (flow.service.empty()) {
                        ImGui::TextDisabled("--");
                    } else {
                        drawDot(serviceColor(flow.service));
                        ImGui::SameLine();
                        ImGui::TextColored(kText1, "%s", flow.service.c_str());
                    }
                    ImGui::TableSetColumnIndex(4);
                    const std::string protocolAndPort = flow.key.protocol + ":" + std::to_string(flow.key.dstPort);
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
                        const float fraction = m_maxFlowBytes == 0
                            ? 0.0f
                            : static_cast<float>(totalBytes) / static_cast<float>(m_maxFlowBytes);
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
                    const std::string rate = formatBytes(static_cast<uint64_t>(flow.rateBytesPerSecond)) + "/s";
                    ImGui::TextUnformatted(rate.c_str());
                    ImGui::TableSetColumnIndex(8);
                    if (flow.initialRttMicroseconds > 0) {
                        const double ms = static_cast<double>(flow.initialRttMicroseconds) / 1000.0;
                        // Color the RTT cell by latency: green <50ms, amber <200ms, red beyond.
                        const ImVec4& rttColor = ms < 50.0 ? kSuccess
                                              : ms < 200.0 ? kWarning : kDanger;
                        ImGui::TextColored(rttColor, "%.1f ms", ms);
                    } else {
                        ImGui::TextDisabled("--");
                    }
                    ImGui::TableSetColumnIndex(9);
                    if (flow.key.protocol != "TCP") {
                        // Only TCP carries the sequence numbers this is derived from.
                        ImGui::TextDisabled("--");
                    } else {
                        const uint64_t retransmissions = retransmissionsOf(flow);
                        const double rate = retransmissionRateOf(flow);
                        // A couple of percent is where a connection stops
                        // feeling fast, so that is where the colour turns.
                        const ImVec4& rateColor = rate < 2.0 ? kSuccess
                                                : rate < 5.0 ? kWarning : kDanger;
                        ImGui::TextColored(rateColor, "%.1f%%", rate);
                        if ((retransmissions > 0 || outOfOrderOf(flow) > 0)
                            && ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
                            ImGui::SetTooltip(
                                "%llu retransmitted, %llu out of order, of %llu packets",
                                static_cast<unsigned long long>(retransmissions),
                                static_cast<unsigned long long>(outOfOrderOf(flow)),
                                static_cast<unsigned long long>(flow.packets));
                        }
                    }
                    ImGui::TableSetColumnIndex(10);
                    const std::string duration = formatDuration(flow.firstSeen, flow.lastSeen);
                    ImGui::TextUnformatted(duration.c_str());
                    ImGui::TableSetColumnIndex(11);
                    if (flow.process.empty()) {
                        ImGui::TextDisabled("--");
                    } else {
                        ImGui::TextColored(kText1, "%s", flow.process.c_str());
                        if (ImGui::IsItemHovered(ImGuiHoveredFlags_ForTooltip)) {
                            ImGui::SetTooltip("%s", flow.process.c_str());
                        }
                    }
                    ImGui::PopID();
                }
            }

            ImGui::EndTable();
        }

        if (showDetail) {
            ImGui::EndChild();
            ImGui::SameLine();
            ImGui::PushStyleColor(ImGuiCol_ChildBg, kBgSurface);
            ImGui::PushStyleVar(ImGuiStyleVar_ChildRounding, 10.0f);
            ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(14, 12));
            if (ImGui::BeginChild("##flowDetail", ImVec2(detailWidth, 0), true)) {
                renderFlowDetail(*selectedFlow, geoFor(selectedFlow->key.dstIP));
            }
            ImGui::EndChild();
            ImGui::PopStyleVar(2);
            ImGui::PopStyleColor();
        }

        ImGui::End();
    }

} // namespace ui
