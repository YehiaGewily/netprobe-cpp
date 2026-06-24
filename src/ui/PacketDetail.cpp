#include "ui/GuiLayer.hpp"
#include "ui/GuiTheme.hpp"
#include "imgui.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <string>

namespace ui {

    namespace {

        // Two-column key/value row with right-aligned-ish key style.
        void kv(const char* key, const std::string& value) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextColored(kText3, "%s", key);
            ImGui::TableSetColumnIndex(1);
            if (value.empty()) {
                ImGui::TextDisabled("--");
            } else {
                ImGui::TextColored(kText1, "%s", value.c_str());
            }
        }

        void kvColored(const char* key, const std::string& value, const ImVec4& color) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::TextColored(kText3, "%s", key);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextColored(color, "%s", value.empty() ? "--" : value.c_str());
        }

        // Group header row that spans both columns of the field table.
        void groupHeader(const char* label) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Spacing();
            ImGui::TextColored(kAccent, "%s", label);
            ImGui::TableSetColumnIndex(1);
        }

        std::string formatTimestamp(int64_t micros) {
            const auto tp = std::chrono::sys_time<std::chrono::microseconds>{
                std::chrono::microseconds{micros}
            };
            const auto sec = std::chrono::floor<std::chrono::seconds>(tp);
            const auto millis = std::chrono::duration_cast<std::chrono::milliseconds>(tp - sec).count();
            return std::format("{:%Y-%m-%d %H:%M:%S}.{:03}", sec, millis);
        }

        void renderHexDump(const std::vector<uint8_t>& bytes, ImFont* mono) {
            if (bytes.empty()) {
                ImGui::TextDisabled("No payload bytes captured.");
                return;
            }
            if (mono) ImGui::PushFont(mono);

            // Classic xxd-style layout: 16 bytes per row, two 8-byte groups,
            // then a printable-ASCII column. Build one line at a time so we
            // can color the gutter, hex, and ASCII independently.
            char line[128];
            for (size_t row = 0; row < bytes.size(); row += 16) {
                const size_t rowLen = std::min<size_t>(16, bytes.size() - row);

                // Offset gutter
                std::snprintf(line, sizeof(line), "%04zx  ", row);
                ImGui::TextColored(kText3, "%s", line);
                ImGui::SameLine(0.0f, 0.0f);

                // Hex bytes
                std::string hex;
                hex.reserve(50);
                for (size_t i = 0; i < 16; ++i) {
                    if (i == 8) hex.push_back(' ');
                    if (i < rowLen) {
                        char b[4];
                        std::snprintf(b, sizeof(b), "%02x ", bytes[row + i]);
                        hex.append(b);
                    } else {
                        hex.append("   ");
                    }
                }
                ImGui::TextColored(kText1, "%s", hex.c_str());
                ImGui::SameLine(0.0f, 8.0f);

                // ASCII
                std::string ascii;
                ascii.reserve(20);
                ascii.push_back('|');
                for (size_t i = 0; i < rowLen; ++i) {
                    const uint8_t b = bytes[row + i];
                    ascii.push_back((b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.');
                }
                ascii.push_back('|');
                ImGui::TextColored(kText2, "%s", ascii.c_str());
            }
            if (mono) ImGui::PopFont();
        }

    }

    void GuiLayer::renderPacketDetail() {
        ImGui::Begin("Packet Detail");

        if (m_selectedPacketIndex < 0
            || m_selectedPacketIndex >= static_cast<int>(m_packetHistory.size())) {
            ImGui::TextColored(kText3,
                "Select a packet in the Live Packets table to inspect its layers and bytes.");
            ImGui::End();
            return;
        }

        const auto& record = m_packetHistory[static_cast<size_t>(m_selectedPacketIndex)];
        const auto& p = record.parsed;

        // Header strip: brief packet identity + a clear-selection button so the
        // user can return to the empty state.
        ImGui::TextColored(kText3, "PACKET #%d", m_selectedPacketIndex);
        ImGui::SameLine();
        if (ImGui::SmallButton("Clear selection")) {
            m_selectedPacketIndex = -1;
            ImGui::End();
            return;
        }
        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // --- Decoded layers ------------------------------------------------
        constexpr ImGuiTableFlags kFieldFlags =
            ImGuiTableFlags_SizingFixedFit | ImGuiTableFlags_NoBordersInBody;
        if (ImGui::BeginTable("PacketFields", 2, kFieldFlags)) {
            ImGui::TableSetupColumn("##key", ImGuiTableColumnFlags_WidthFixed, 110.0f);
            ImGui::TableSetupColumn("##value", ImGuiTableColumnFlags_WidthStretch);

            groupHeader("Frame");
            kv("Timestamp", formatTimestamp(p.timestamp));
            kv("Wire length", std::format("{} bytes", record.raw.length));
            kv("Captured", std::format("{} bytes", record.raw.capturedLength));

            groupHeader("Network");
            kv("Source IP", p.srcIP);
            kv("Dest IP", p.dstIP);
            kvColored("Protocol", p.protocol, protocolColor(p.protocol));

            if (p.srcPort != 0 || p.dstPort != 0) {
                groupHeader("Transport");
                kv("Source port", std::format("{}", p.srcPort));
                kv("Dest port", std::format("{}", p.dstPort));
            }

            groupHeader("Application");
            if (!p.service.empty()) {
                kvColored("Service", p.service, serviceColor(p.service));
            } else {
                kv("Service", "");
            }
            kv("SNI", p.sni);
            if (auto host = m_hostnameCache.lookup(p.dstIP)) {
                kv("Hostname", *host);
            } else if (auto host2 = m_hostnameCache.lookup(p.srcIP)) {
                kv("Hostname", *host2);
            } else {
                kv("Hostname", "");
            }
            if (const std::string app = m_processResolver.lookup(p); !app.empty()) {
                kv("Process", app);
            } else {
                kv("Process", "");
            }

            ImGui::EndTable();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();

        // --- Hex dump ------------------------------------------------------
        ImGui::TextColored(kText3, "RAW BYTES");
        ImGui::SameLine();
        ImGui::TextDisabled("(%u bytes captured)", record.raw.capturedLength);
        ImGui::Spacing();

        if (ImGui::BeginChild("##hexScroll", ImVec2(0, 0), false,
                ImGuiWindowFlags_HorizontalScrollbar)) {
            renderHexDump(record.raw.payload, m_fontMono);
        }
        ImGui::EndChild();

        ImGui::End();
    }

} // namespace ui
