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
    inline ImVec4 kBgBase      = ImVec4(0.035f, 0.039f, 0.051f, 1.00f); // #090A0D
    inline ImVec4 kBgSurface   = ImVec4(0.047f, 0.055f, 0.075f, 1.00f); // #0C0E13
    inline ImVec4 kBgElevated  = ImVec4(0.071f, 0.078f, 0.106f, 1.00f); // #12141B
    inline ImVec4 kBgInput     = ImVec4(0.086f, 0.094f, 0.122f, 1.00f); // #16181F
    inline ImVec4 kBorderSoft  = ImVec4(0.102f, 0.110f, 0.141f, 1.00f); // #1A1C24
    inline ImVec4 kBorder      = ImVec4(0.149f, 0.165f, 0.204f, 1.00f); // #262A34

    inline ImVec4 kBgHover     = ImVec4(0.110f, 0.122f, 0.157f, 1.00f); // #1C1F28
    inline ImVec4 kBgActive    = ImVec4(0.149f, 0.169f, 0.216f, 1.00f); // #262B37

    inline ImVec4 kText1       = ImVec4(0.957f, 0.965f, 0.980f, 1.00f); // #F4F6FA
    inline ImVec4 kText2       = ImVec4(0.604f, 0.643f, 0.702f, 1.00f); // #9AA4B3
    inline ImVec4 kText3       = ImVec4(0.357f, 0.392f, 0.451f, 1.00f); // #5B6473

    inline ImVec4 kAccent      = ImVec4(0.176f, 0.831f, 0.933f, 1.00f); // #2DD4EE  site cyan
    inline ImVec4 kAccentSoft  = ImVec4(0.176f, 0.831f, 0.933f, 0.20f);
    inline ImVec4 kAccentFaint = ImVec4(0.176f, 0.831f, 0.933f, 0.10f);
    inline ImVec4 kSuccess     = ImVec4(0.204f, 0.827f, 0.600f, 1.00f); // #34D399 emerald
    inline ImVec4 kWarning     = ImVec4(0.984f, 0.749f, 0.141f, 1.00f); // #FBBF24
    inline ImVec4 kDanger      = ImVec4(0.973f, 0.443f, 0.443f, 1.00f); // #F87171

    // Brand gradient — the website's cyan → blue → violet system. Constant
    // across themes because it is only ever painted as a fill under white or
    // dark shapes, never used as text. Endpoints match docs/styles.css --grad.
    inline constexpr ImVec4 kGradStart = ImVec4(0.176f, 0.831f, 0.933f, 1.00f); // #2DD4EE
    inline constexpr ImVec4 kGradMid   = ImVec4(0.310f, 0.545f, 0.961f, 1.00f); // #4F8BF5
    inline constexpr ImVec4 kGradEnd   = ImVec4(0.486f, 0.435f, 0.941f, 1.00f); // #7C6FF0

    inline void applyPalette(bool dark) {
        kIsDarkTheme = dark;
        if (dark) {
            kBgBase      = ImVec4(0.035f, 0.039f, 0.051f, 1.00f); // #090A0D
            kBgSurface   = ImVec4(0.047f, 0.055f, 0.075f, 1.00f); // #0C0E13
            kBgElevated  = ImVec4(0.071f, 0.078f, 0.106f, 1.00f); // #12141B
            kBgInput     = ImVec4(0.086f, 0.094f, 0.122f, 1.00f); // #16181F
            kBorderSoft  = ImVec4(0.102f, 0.110f, 0.141f, 1.00f); // #1A1C24
            kBorder      = ImVec4(0.149f, 0.165f, 0.204f, 1.00f); // #262A34
            kBgHover     = ImVec4(0.110f, 0.122f, 0.157f, 1.00f); // #1C1F28
            kBgActive    = ImVec4(0.149f, 0.169f, 0.216f, 1.00f); // #262B37
            kText1       = ImVec4(0.957f, 0.965f, 0.980f, 1.00f); // #F4F6FA
            kText2       = ImVec4(0.604f, 0.643f, 0.702f, 1.00f); // #9AA4B3
            kText3       = ImVec4(0.357f, 0.392f, 0.451f, 1.00f); // #5B6473
            kSuccess     = ImVec4(0.204f, 0.827f, 0.600f, 1.00f); // #34D399
            kWarning     = ImVec4(0.984f, 0.749f, 0.141f, 1.00f); // #FBBF24
            kDanger      = ImVec4(0.973f, 0.443f, 0.443f, 1.00f); // #F87171
        } else {
            kBgBase      = ImVec4(0.961f, 0.969f, 0.984f, 1.00f); // #F5F7FB
            kBgSurface   = ImVec4(1.000f, 1.000f, 1.000f, 1.00f); // #FFFFFF
            kBgElevated  = ImVec4(1.000f, 1.000f, 1.000f, 1.00f); // #FFFFFF
            kBgInput     = ImVec4(0.929f, 0.945f, 0.969f, 1.00f); // #EDF1F7
            kBorderSoft  = ImVec4(0.886f, 0.910f, 0.941f, 1.00f); // #E2E8F0
            kBorder      = ImVec4(0.796f, 0.835f, 0.882f, 1.00f); // #CBD5E1
            kBgHover     = ImVec4(0.906f, 0.929f, 0.961f, 1.00f); // #E7EDF5
            kBgActive    = ImVec4(0.847f, 0.878f, 0.925f, 1.00f); // #D8E0EC
            kText1       = ImVec4(0.059f, 0.090f, 0.165f, 1.00f); // #0F172A
            kText2       = ImVec4(0.278f, 0.333f, 0.412f, 1.00f); // #475569
            kText3       = ImVec4(0.541f, 0.592f, 0.659f, 1.00f); // #8A97A8
            kSuccess     = ImVec4(0.086f, 0.639f, 0.290f, 1.00f); // #16A34A
            kWarning     = ImVec4(0.710f, 0.400f, 0.020f, 1.00f); // #B56605
            kDanger      = ImVec4(0.863f, 0.149f, 0.149f, 1.00f); // #DC2626
        }
        // Cyan reads brilliantly on the dark canvas but washes out on white, so
        // the light theme anchors the solid accent on the gradient's blue mid
        // stop; the gradient fills themselves stay cyan→violet on both canvases.
        kAccent      = dark ? ImVec4(0.176f, 0.831f, 0.933f, 1.00f)  // #2DD4EE cyan
                            : ImVec4(0.310f, 0.545f, 0.961f, 1.00f); // #4F8BF5 blue
        kAccentSoft  = ImVec4(kAccent.x, kAccent.y, kAccent.z, dark ? 0.20f : 0.26f);
        kAccentFaint = ImVec4(kAccent.x, kAccent.y, kAccent.z, dark ? 0.10f : 0.14f);
    }

    // Linear interpolation between two colors.
    inline ImVec4 lerpVec4(const ImVec4& a, const ImVec4& b, float t) {
        return ImVec4(a.x + (b.x - a.x) * t, a.y + (b.y - a.y) * t,
                      a.z + (b.z - a.z) * t, a.w + (b.w - a.w) * t);
    }

    // Sample the three-stop brand gradient at t in [0,1].
    inline ImVec4 gradSample(float t) {
        t = t < 0.0f ? 0.0f : (t > 1.0f ? 1.0f : t);
        return t < 0.5f ? lerpVec4(kGradStart, kGradMid, t * 2.0f)
                        : lerpVec4(kGradMid, kGradEnd, (t - 0.5f) * 2.0f);
    }

    // Horizontal cyan→violet gradient fill for hero elements (KPI caps, share
    // bars, the toolbar hairline). t0/t1 map the brand gradient to the left and
    // right edges so a partial-width bar still shows a continuous sweep. Corners
    // are square — multi-color fills cannot round, which is invisible on the
    // thin strips this is used for.
    inline void drawGradientRectH(ImDrawList* dl, const ImVec2& a, const ImVec2& b,
                                  float alpha = 1.0f, float t0 = 0.0f, float t1 = 1.0f) {
        ImVec4 cl = gradSample(t0); cl.w = alpha;
        ImVec4 cr = gradSample(t1); cr.w = alpha;
        const ImU32 l = ImGui::GetColorU32(cl);
        const ImU32 r = ImGui::GetColorU32(cr);
        dl->AddRectFilledMultiColor(a, b, l, r, r, l);
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
            if (protocol == "TCP")  return ImVec4(0.506f, 0.549f, 0.973f, 1.0f); // #818CF8 indigo
            if (protocol == "UDP")  return ImVec4(0.204f, 0.827f, 0.600f, 1.0f); // #34D399 emerald
            if (protocol == "ICMP") return ImVec4(0.961f, 0.706f, 0.294f, 1.0f); // #F5B44B amber
        } else {
            if (protocol == "TCP")  return ImVec4(0.310f, 0.275f, 0.898f, 1.0f); // #4F46E5
            if (protocol == "UDP")  return ImVec4(0.055f, 0.624f, 0.431f, 1.0f); // #0E9F6E
            if (protocol == "ICMP") return ImVec4(0.710f, 0.400f, 0.020f, 1.0f); // #B56605
        }
        return kText3;
    }

    // Stable accent color for a service tag based on a small hash.
    // Muted Linear-style palette so different services read as siblings, not
    // competing accents. Each hue has a darker sibling for the light theme.
    inline ImVec4 serviceColor(const std::string& service) {
        if (service.empty()) return kText3;
        constexpr std::array<ImVec4, 6> dark = {
            ImVec4(0.506f, 0.549f, 0.973f, 1.0f), // #818CF8 indigo
            ImVec4(0.204f, 0.827f, 0.600f, 1.0f), // #34D399 emerald
            ImVec4(0.984f, 0.541f, 0.420f, 1.0f), // #FB8A6B coral
            ImVec4(0.655f, 0.545f, 0.980f, 1.0f), // #A78BFA violet
            ImVec4(0.961f, 0.769f, 0.318f, 1.0f), // #F5C451 sand
            ImVec4(0.220f, 0.741f, 0.973f, 1.0f), // #38BDF8 sky
        };
        constexpr std::array<ImVec4, 6> light = {
            ImVec4(0.310f, 0.275f, 0.898f, 1.0f), // #4F46E5 indigo
            ImVec4(0.055f, 0.624f, 0.431f, 1.0f), // #0E9F6E emerald
            ImVec4(0.863f, 0.353f, 0.235f, 1.0f), // #DC5A3C coral
            ImVec4(0.486f, 0.227f, 0.929f, 1.0f), // #7C3AED violet
            ImVec4(0.706f, 0.502f, 0.102f, 1.0f), // #B4801A sand
            ImVec4(0.008f, 0.518f, 0.780f, 1.0f), // #0284C7 sky
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
