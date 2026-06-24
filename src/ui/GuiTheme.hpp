#pragma once

#include "imgui.h"

#include <array>
#include <chrono>
#include <cstdint>
#include <format>
#include <string>

// Shared visual tokens and small drawing helpers used by every UI view.
// Keeping these in one header lets the per-view .cpp files stay small and
// independent without duplicating the palette or formatting logic.
namespace ui {

    // Linear-inspired palette: near-black canvas, soft borders, single violet accent.
    inline constexpr ImVec4 kBgBase      = ImVec4(0.039f, 0.039f, 0.047f, 1.00f); // #0A0A0C
    inline constexpr ImVec4 kBgSurface   = ImVec4(0.075f, 0.075f, 0.094f, 1.00f); // #131318
    inline constexpr ImVec4 kBgElevated  = ImVec4(0.102f, 0.102f, 0.125f, 1.00f); // #1A1A20
    inline constexpr ImVec4 kBgInput     = ImVec4(0.117f, 0.117f, 0.149f, 1.00f); // #1E1E26
    inline constexpr ImVec4 kBorderSoft  = ImVec4(0.122f, 0.122f, 0.149f, 1.00f); // #1F1F26
    inline constexpr ImVec4 kBorder      = ImVec4(0.165f, 0.165f, 0.208f, 1.00f); // #2A2A35

    inline constexpr ImVec4 kText1       = ImVec4(0.925f, 0.925f, 0.933f, 1.00f); // #ECECEE
    inline constexpr ImVec4 kText2       = ImVec4(0.600f, 0.600f, 0.639f, 1.00f); // #9999A3
    inline constexpr ImVec4 kText3       = ImVec4(0.361f, 0.361f, 0.408f, 1.00f); // #5C5C68

    inline constexpr ImVec4 kAccent      = ImVec4(0.369f, 0.416f, 0.824f, 1.00f); // #5E6AD2  Linear violet-blue
    inline constexpr ImVec4 kAccentSoft  = ImVec4(0.369f, 0.416f, 0.824f, 0.22f);
    inline constexpr ImVec4 kAccentFaint = ImVec4(0.369f, 0.416f, 0.824f, 0.10f);
    inline constexpr ImVec4 kSuccess     = ImVec4(0.290f, 0.871f, 0.502f, 1.00f); // #4ADE80
    inline constexpr ImVec4 kWarning     = ImVec4(0.984f, 0.749f, 0.141f, 1.00f); // #FBBF24
    inline constexpr ImVec4 kDanger      = ImVec4(0.973f, 0.443f, 0.443f, 1.00f); // #F87171

    inline int64_t currentUnixTimeMicroseconds() {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    inline std::string formatBytes(uint64_t bytes) {
        constexpr std::array<const char*, 4> units = {"B", "KB", "MB", "GB"};
        double value = static_cast<double>(bytes);
        size_t unit = 0;
        while (value >= 1024.0 && unit + 1 < units.size()) {
            value /= 1024.0;
            ++unit;
        }
        return unit == 0
            ? std::format("{} {}", bytes, units[unit])
            : std::format("{:.1f} {}", value, units[unit]);
    }

    inline std::string formatCount(uint64_t value) {
        if (value < 1000) return std::format("{}", value);
        if (value < 1'000'000) return std::format("{:.1f}K", value / 1000.0);
        if (value < 1'000'000'000) return std::format("{:.1f}M", value / 1'000'000.0);
        return std::format("{:.1f}B", value / 1'000'000'000.0);
    }

    inline std::string formatDuration(int64_t firstSeen, int64_t lastSeen) {
        const int64_t seconds = std::max<int64_t>(0, (lastSeen - firstSeen) / 1'000'000);
        return std::format("{:02}:{:02}:{:02}", seconds / 3600, (seconds / 60) % 60, seconds % 60);
    }

    inline ImVec4 protocolColor(const std::string& protocol) {
        if (protocol == "TCP")  return ImVec4(0.55f, 0.66f, 0.92f, 1.0f);
        if (protocol == "UDP")  return ImVec4(0.55f, 0.78f, 0.55f, 1.0f);
        if (protocol == "ICMP") return ImVec4(0.84f, 0.69f, 0.43f, 1.0f);
        return kText3;
    }

    // Stable accent color for a service tag based on a small hash.
    // Muted Linear-style palette so different services read as siblings, not
    // competing accents.
    inline ImVec4 serviceColor(const std::string& service) {
        if (service.empty()) return kText3;
        constexpr std::array<ImVec4, 6> palette = {
            ImVec4(0.45f, 0.52f, 0.91f, 1.0f), // indigo
            ImVec4(0.50f, 0.78f, 0.69f, 1.0f), // teal
            ImVec4(0.91f, 0.62f, 0.52f, 1.0f), // coral
            ImVec4(0.71f, 0.61f, 0.91f, 1.0f), // lavender
            ImVec4(0.84f, 0.73f, 0.45f, 1.0f), // sand
            ImVec4(0.55f, 0.78f, 0.55f, 1.0f), // moss
        };
        size_t h = 0;
        for (char c : service) h = h * 131u + static_cast<unsigned char>(c);
        return palette[h % palette.size()];
    }

    // Small colored dot inline with text; advances the cursor.
    inline void drawDot(const ImVec4& color, float radius = 3.5f) {
        const ImVec2 pos = ImGui::GetCursorScreenPos();
        const float yMid = pos.y + ImGui::GetTextLineHeight() * 0.5f;
        ImGui::GetWindowDrawList()->AddCircleFilled(
            ImVec2(pos.x + radius + 2.0f, yMid), radius,
            ImGui::GetColorU32(color));
        ImGui::Dummy(ImVec2(radius * 2.0f + 8.0f, ImGui::GetTextLineHeight()));
    }

} // namespace ui
