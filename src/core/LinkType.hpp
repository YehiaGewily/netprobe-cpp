#pragma once

#include <cstdint>

namespace core {

    // The link-layer encapsulation a capture was recorded with. libpcap reports
    // this per handle via pcap_datalink(); it is NOT always Ethernet. Loopback
    // interfaces, Linux's "any" pseudo-device, and tunnel interfaces all use
    // different (or absent) L2 headers, and misreading them silently produces
    // garbage addresses rather than an error.
    enum class LinkType : uint8_t {
        Ethernet,     // DLT_EN10MB — 14-byte Ethernet II header
        RawIP,        // DLT_RAW — no L2 header, IP version taken from first nibble
        NullLoopback, // DLT_NULL — 4-byte host-endian address family
        Loop,         // DLT_LOOP — 4-byte big-endian address family
        LinuxSLL,     // DLT_LINUX_SLL — 16-byte cooked header
        LinuxSLL2,    // DLT_LINUX_SLL2 — 20-byte cooked header v2
        IPv4,         // DLT_IPV4 — bare IPv4
        IPv6,         // DLT_IPV6 — bare IPv6
        Unsupported,  // Anything we cannot decode (802.11 radiotap, etc.)
    };

    // libpcap DLT_* values. Declared here rather than including pcap.h so the
    // core parsing layer stays free of the capture dependency (the fuzzers and
    // unit tests build core/ without libpcap).
    inline constexpr int kDltNull       = 0;
    inline constexpr int kDltEn10Mb     = 1;
    inline constexpr int kDltRaw        = 12;   // On some platforms 14; both are handled.
    inline constexpr int kDltRawAlt     = 14;
    inline constexpr int kDltLoop       = 108;
    inline constexpr int kDltLinuxSll   = 113;
    inline constexpr int kDltIpv4       = 228;
    inline constexpr int kDltIpv6       = 229;
    inline constexpr int kDltLinuxSll2  = 276;

    inline LinkType linkTypeFromDlt(int dlt) {
        switch (dlt) {
        case kDltEn10Mb:    return LinkType::Ethernet;
        case kDltNull:      return LinkType::NullLoopback;
        case kDltLoop:      return LinkType::Loop;
        case kDltRaw:
        case kDltRawAlt:    return LinkType::RawIP;
        case kDltLinuxSll:  return LinkType::LinuxSLL;
        case kDltLinuxSll2: return LinkType::LinuxSLL2;
        case kDltIpv4:      return LinkType::IPv4;
        case kDltIpv6:      return LinkType::IPv6;
        default:            return LinkType::Unsupported;
        }
    }

    inline int dltFromLinkType(LinkType link) {
        switch (link) {
        case LinkType::Ethernet:     return kDltEn10Mb;
        case LinkType::NullLoopback: return kDltNull;
        case LinkType::Loop:         return kDltLoop;
        case LinkType::RawIP:        return kDltRaw;
        case LinkType::LinuxSLL:     return kDltLinuxSll;
        case LinkType::LinuxSLL2:    return kDltLinuxSll2;
        case LinkType::IPv4:         return kDltIpv4;
        case LinkType::IPv6:         return kDltIpv6;
        case LinkType::Unsupported:  break;
        }
        return kDltEn10Mb;
    }

    inline const char* linkTypeName(LinkType link) {
        switch (link) {
        case LinkType::Ethernet:     return "Ethernet";
        case LinkType::RawIP:        return "Raw IP";
        case LinkType::NullLoopback: return "Loopback (BSD)";
        case LinkType::Loop:         return "Loopback (OpenBSD)";
        case LinkType::LinuxSLL:     return "Linux cooked";
        case LinkType::LinuxSLL2:    return "Linux cooked v2";
        case LinkType::IPv4:         return "Raw IPv4";
        case LinkType::IPv6:         return "Raw IPv6";
        case LinkType::Unsupported:  return "Unsupported";
        }
        return "Unknown";
    }

} // namespace core
