#pragma once

#include "imgui.h"

#include <array>
#include <chrono>
#include <cstdio>
#include <cstdint>
#include <string>

// Shared visual tokens and small drawing helpers used by every UI view.
// Keeping these in one header lets the per-view .cpp files stay small and
// independent without duplicating the palette or formatting logic.
namespace ui {

    // Runtime palette. Every view references these tokens directly, so
    // applyPalette() can flip the whole application between the dark and
    // light themes without any per-view changes. Defaults are the dark
    // (Linear-inspired) palette so code that reads a token before init()
    // still gets sensible colors.
    inline bool   kIsDarkTheme = true;
    inline ImVec4 kBgBase      = ImVec4(0.039f, 0.039f, 0.047f, 1.00f); // #0A0A0C
    inline ImVec4 kBgSurface   = ImVec4(0.075f, 0.075f, 0.094f, 1.00f); // #131318
    inline ImVec4 kBgElevated  = ImVec4(0.102f, 0.102f, 0.125f, 1.00f); // #1A1A20
    inline ImVec4 kBgInput     = ImVec4(0.117f, 0.117f, 0.149f, 1.00f); // #1E1E26
    inline ImVec4 kBorderSoft  = ImVec4(0.122f, 0.122f, 0.149f, 1.00f); // #1F1F26
    inline ImVec4 kBorder      = ImVec4(0.165f, 0.165f, 0.208f, 1.00f); // #2A2A35

    inline ImVec4 kBgHover     = ImVec4(0.149f, 0.149f, 0.184f, 1.00f); // #26262F
    inline ImVec4 kBgActive    = ImVec4(0.196f, 0.196f, 0.243f, 1.00f); // #32323E

    inline ImVec4 kText1       = ImVec4(0.925f, 0.925f, 0.933f, 1.00f); // #ECECEE
    inline ImVec4 kText2       = ImVec4(0.600f, 0.600f, 0.639f, 1.00f); // #9999A3
    inline ImVec4 kText3       = ImVec4(0.361f, 0.361f, 0.408f, 1.00f); // #5C5C68

    inline ImVec4 kAccent      = ImVec4(0.369f, 0.416f, 0.824f, 1.00f); // #5E6AD2  Linear violet-blue
    inline ImVec4 kAccentSoft  = ImVec4(0.369f, 0.416f, 0.824f, 0.22f);
    inline ImVec4 kAccentFaint = ImVec4(0.369f, 0.416f, 0.824f, 0.10f);
    inline ImVec4 kSuccess     = ImVec4(0.290f, 0.871f, 0.502f, 1.00f); // #4ADE80
    inline ImVec4 kWarning     = ImVec4(0.984f, 0.749f, 0.141f, 1.00f); // #FBBF24
    inline ImVec4 kDanger      = ImVec4(0.973f, 0.443f, 0.443f, 1.00f); // #F87171

    inline void applyPalette(bool dark) {
        kIsDarkTheme = dark;
        if (dark) {
            kBgBase      = ImVec4(0.039f, 0.039f, 0.047f, 1.00f); // #0A0A0C
            kBgSurface   = ImVec4(0.075f, 0.075f, 0.094f, 1.00f); // #131318
            kBgElevated  = ImVec4(0.102f, 0.102f, 0.125f, 1.00f); // #1A1A20
            kBgInput     = ImVec4(0.117f, 0.117f, 0.149f, 1.00f); // #1E1E26
            kBorderSoft  = ImVec4(0.122f, 0.122f, 0.149f, 1.00f); // #1F1F26
            kBorder      = ImVec4(0.165f, 0.165f, 0.208f, 1.00f); // #2A2A35
            kBgHover     = ImVec4(0.149f, 0.149f, 0.184f, 1.00f); // #26262F
            kBgActive    = ImVec4(0.196f, 0.196f, 0.243f, 1.00f); // #32323E
            kText1       = ImVec4(0.925f, 0.925f, 0.933f, 1.00f); // #ECECEE
            kText2       = ImVec4(0.600f, 0.600f, 0.639f, 1.00f); // #9999A3
            kText3       = ImVec4(0.361f, 0.361f, 0.408f, 1.00f); // #5C5C68
            kSuccess     = ImVec4(0.290f, 0.871f, 0.502f, 1.00f); // #4ADE80
            kWarning     = ImVec4(0.984f, 0.749f, 0.141f, 1.00f); // #FBBF24
            kDanger      = ImVec4(0.973f, 0.443f, 0.443f, 1.00f); // #F87171
        } else {
            kBgBase      = ImVec4(0.973f, 0.973f, 0.980f, 1.00f); // #F8F8FA
            kBgSurface   = ImVec4(1.000f, 1.000f, 1.000f, 1.00f); // #FFFFFF
            kBgElevated  = ImVec4(1.000f, 1.000f, 1.000f, 1.00f); // #FFFFFF
            kBgInput     = ImVec4(0.929f, 0.929f, 0.949f, 1.00f); // #EDEDF2
            kBorderSoft  = ImVec4(0.894f, 0.894f, 0.918f, 1.00f); // #E4E4EA
            kBorder      = ImVec4(0.831f, 0.831f, 0.863f, 1.00f); // #D4D4DC
            kBgHover     = ImVec4(0.882f, 0.882f, 0.910f, 1.00f); // #E1E1E8
            kBgActive    = ImVec4(0.831f, 0.831f, 0.871f, 1.00f); // #D4D4DE
            kText1       = ImVec4(0.102f, 0.102f, 0.129f, 1.00f); // #1A1A21
            kText2       = ImVec4(0.361f, 0.361f, 0.408f, 1.00f); // #5C5C68
            kText3       = ImVec4(0.580f, 0.580f, 0.627f, 1.00f); // #9494A0
            kSuccess     = ImVec4(0.086f, 0.639f, 0.290f, 1.00f); // #16A34A
            kWarning     = ImVec4(0.710f, 0.400f, 0.020f, 1.00f); // #B56605
            kDanger      = ImVec4(0.863f, 0.149f, 0.149f, 1.00f); // #DC2626
        }
        // The accent works on both canvases; only its translucent tints change
        // strength so hover/selection states stay visible on white.
        kAccent      = ImVec4(0.369f, 0.416f, 0.824f, 1.00f);     // #5E6AD2
        kAccentSoft  = ImVec4(0.369f, 0.416f, 0.824f, dark ? 0.22f : 0.28f);
        kAccentFaint = ImVec4(0.369f, 0.416f, 0.824f, dark ? 0.10f : 0.14f);
    }

    inline int64_t currentUnixTimeMicroseconds() {
        return std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }

    inline std::string formatFloat(double value, int precision) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.*f", precision, value);
        return std::string(buf);
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
            ? (std::to_string(bytes) + " " + units[unit])
            : (formatFloat(value, 1) + " " + units[unit]);
    }

    inline std::string formatCount(uint64_t value) {
        if (value < 1000) return std::to_string(value);
        if (value < 1'000'000) return formatFloat(value / 1000.0, 1) + "K";
        if (value < 1'000'000'000) return formatFloat(value / 1'000'000.0, 1) + "M";
        return formatFloat(value / 1'000'000'000.0, 1) + "B";
    }

    inline std::string formatDuration(int64_t firstSeen, int64_t lastSeen) {
        const int64_t seconds = std::max<int64_t>(0, (lastSeen - firstSeen) / 1'000'000);
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%02lld:%02lld:%02lld",
            static_cast<long long>(seconds / 3600),
            static_cast<long long>((seconds / 60) % 60),
            static_cast<long long>(seconds % 60));
        return std::string(buf);
    }

    inline ImVec4 protocolColor(const std::string& protocol) {
        if (kIsDarkTheme) {
            if (protocol == "TCP")  return ImVec4(0.55f, 0.66f, 0.92f, 1.0f);
            if (protocol == "UDP")  return ImVec4(0.55f, 0.78f, 0.55f, 1.0f);
            if (protocol == "ICMP") return ImVec4(0.84f, 0.69f, 0.43f, 1.0f);
        } else {
            if (protocol == "TCP")  return ImVec4(0.24f, 0.35f, 0.72f, 1.0f);
            if (protocol == "UDP")  return ImVec4(0.16f, 0.52f, 0.26f, 1.0f);
            if (protocol == "ICMP") return ImVec4(0.66f, 0.45f, 0.10f, 1.0f);
        }
        return kText3;
    }

    // Stable accent color for a service tag based on a small hash.
    // Muted Linear-style palette so different services read as siblings, not
    // competing accents. Each hue has a darker sibling for the light theme.
    inline ImVec4 serviceColor(const std::string& service) {
        if (service.empty()) return kText3;
        constexpr std::array<ImVec4, 6> dark = {
            ImVec4(0.45f, 0.52f, 0.91f, 1.0f), // indigo
            ImVec4(0.50f, 0.78f, 0.69f, 1.0f), // teal
            ImVec4(0.91f, 0.62f, 0.52f, 1.0f), // coral
            ImVec4(0.71f, 0.61f, 0.91f, 1.0f), // lavender
            ImVec4(0.84f, 0.73f, 0.45f, 1.0f), // sand
            ImVec4(0.55f, 0.78f, 0.55f, 1.0f), // moss
        };
        constexpr std::array<ImVec4, 6> light = {
            ImVec4(0.27f, 0.34f, 0.75f, 1.0f), // indigo
            ImVec4(0.13f, 0.52f, 0.44f, 1.0f), // teal
            ImVec4(0.75f, 0.34f, 0.24f, 1.0f), // coral
            ImVec4(0.48f, 0.35f, 0.75f, 1.0f), // lavender
            ImVec4(0.62f, 0.48f, 0.14f, 1.0f), // sand
            ImVec4(0.24f, 0.52f, 0.26f, 1.0f), // moss
        };
        size_t h = 0;
        for (char c : service) h = h * 131u + static_cast<unsigned char>(c);
        return (kIsDarkTheme ? dark : light)[h % dark.size()];
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
