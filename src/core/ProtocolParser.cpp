#include "core/ProtocolParser.hpp"
#include "core/NetworkPlatform.hpp"
#include "core/QuicParser.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <string>
#include <string_view>

namespace core {

    namespace {
        uint16_t readU16(const uint8_t* bytes) {
            return static_cast<uint16_t>(bytes[0]) << 8 | bytes[1];
        }

        std::string ipv4ToString(const uint8_t* bytes) {
            uint32_t address;
            std::memcpy(&address, bytes, sizeof(address));
            char buf[INET_ADDRSTRLEN]{};
            return inet_ntop(AF_INET, &address, buf, sizeof(buf)) ? buf : "";
        }

        std::string ipv6ToString(const uint8_t* bytes) {
            char buf[INET6_ADDRSTRLEN]{};
            return inet_ntop(AF_INET6, bytes, buf, sizeof(buf)) ? buf : "";
        }

        // Map an L4 (or "next header") protocol number to a short label.
        // Returns nullptr for protocols handled elsewhere (TCP / UDP) so the caller
        // can do richer parsing for those.
        const char* ipProtocolName(uint8_t proto) {
            switch (proto) {
                case 1:   return "ICMP";
                case 2:   return "IGMP";
                case 47:  return "GRE";
                case 50:  return "ESP";
                case 51:  return "AH";
                case 58:  return "ICMPv6";
                case 89:  return "OSPF";
                case 132: return "SCTP";
                case 4:   return "IP-in-IP";
                case 41:  return "IPv6-tunnel";
                default:  return nullptr;
            }
        }

        // IPv6 extension header? If so, advances pos by header length and
        // returns the new next-header value via outNext. Returns true if the
        // current value was an extension header. The caller stops walking when
        // this returns false (i.e. we've reached the upper-layer protocol).
        bool walkV6Extension(uint8_t nh, const uint8_t* buffer, size_t size,
                             size_t& pos, uint8_t& outNext) {
            switch (nh) {
                case 0:   // Hop-by-hop
                case 43:  // Routing
                case 60:  // Destination options
                case 135: // Mobility
                {
                    if (size < pos + 2) return false;
                    const uint8_t newNh = buffer[pos];
                    const size_t hdrLen = (static_cast<size_t>(buffer[pos + 1]) + 1) * 8;
                    if (size < pos + hdrLen) return false;
                    pos += hdrLen;
                    outNext = newNh;
                    return true;
                }
                case 44: // Fragment — fixed 8 bytes; the fragment offset matters but
                         // for live DPI we just keep walking on first-fragment.
                {
                    if (size < pos + 8) return false;
                    outNext = buffer[pos];
                    pos += 8;
                    return true;
                }
                case 51: // Auth header (8 + 4 * payload-len). Encrypted payload (50)
                         // would normally terminate parsing, but we don't need to
                         // descend into it for accounting.
                {
                    if (size < pos + 2) return false;
                    outNext = buffer[pos];
                    const size_t hdrLen = (static_cast<size_t>(buffer[pos + 1]) + 2) * 4;
                    if (size < pos + hdrLen) return false;
                    pos += hdrLen;
                    return true;
                }
                default:
                    return false;
            }
        }

        // Lower-case in place for case-insensitive substring matches.
        std::string toLowerCopy(std::string_view s) {
            std::string out(s);
            std::transform(out.begin(), out.end(), out.begin(),
                [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            return out;
        }
    }

    ParsedPacket ProtocolParser::parse(const PacketData& rawData) {
        ParsedPacket parsed;
        parsed.timestamp = rawData.timestamp;
        parsed.length = rawData.length;
        parsed.protocol = "Unknown";

        const uint8_t* buffer = rawData.payload.data();
        const size_t size = rawData.payload.size();
        size_t offset = 0;

        // 1. Ethernet (with optional VLAN tags).
        if (size < sizeof(EthernetHeader)) return parsed;
        offset += sizeof(EthernetHeader);
        uint16_t ethType = readU16(buffer + 12);
        while (ethType == 0x8100 || ethType == 0x88A8 || ethType == 0x9100) {
            if (size < offset + 4) return parsed;
            ethType = readU16(buffer + offset + 2);
            offset += 4;
        }

        // 2. ARP (we extract sender/target protocol addresses when IPv4).
        if (ethType == 0x0806) {
            parsed.protocol = "ARP";
            // ARP frame: HTYPE(2) PTYPE(2) HLEN(1) PLEN(1) OPER(2)
            //            SHA(HLEN) SPA(PLEN) THA(HLEN) TPA(PLEN)
            if (size < offset + 8) return parsed;
            const uint16_t ptype = readU16(buffer + offset + 2);
            const uint8_t hlen = buffer[offset + 4];
            const uint8_t plen = buffer[offset + 5];
            const uint16_t oper = readU16(buffer + offset + 6);
            const size_t arpBody = offset + 8;
            if (ptype == 0x0800 && plen == 4 && size >= arpBody + 2u * (hlen + plen)) {
                parsed.srcIP = ipv4ToString(buffer + arpBody + hlen);
                parsed.dstIP = ipv4ToString(buffer + arpBody + 2u * hlen + plen);
            }
            parsed.service = (oper == 1) ? "ARP request" : (oper == 2) ? "ARP reply" : "";
            return parsed;
        }

        // 3. IP layer.
        uint8_t l4Proto = 0;
        size_t l4Offset = 0;
        size_t packetEnd = size;

        if (ethType == 0x0800) {
            // IPv4
            if (size < offset + sizeof(IPv4Header)) return parsed;
            const uint8_t versionHlen = buffer[offset];
            const uint8_t version = versionHlen >> 4;
            const size_t ihl = (versionHlen & 0x0F) * 4;
            if (version != 4 || ihl < sizeof(IPv4Header) || size < offset + ihl) return parsed;

            const uint16_t totalLength = readU16(buffer + offset + 2);
            if (totalLength < ihl) return parsed;
            packetEnd = std::min(size, offset + static_cast<size_t>(totalLength));

            parsed.srcIP = ipv4ToString(buffer + offset + 12);
            parsed.dstIP = ipv4ToString(buffer + offset + 16);

            const uint16_t flagsFragOff = readU16(buffer + offset + 6);
            if ((flagsFragOff & 0x1FFF) != 0) {
                parsed.protocol = "IPv4 Fragment";
                return parsed;
            }
            l4Proto = buffer[offset + 9];
            l4Offset = offset + ihl;
        } else if (ethType == 0x86DD) {
            // IPv6
            constexpr size_t v6FixedHeader = 40;
            if (size < offset + v6FixedHeader) return parsed;

            const uint16_t payloadLen = readU16(buffer + offset + 4);
            packetEnd = std::min(size, offset + v6FixedHeader + static_cast<size_t>(payloadLen));

            parsed.srcIP = ipv6ToString(buffer + offset + 8);
            parsed.dstIP = ipv6ToString(buffer + offset + 24);

            uint8_t nextHeader = buffer[offset + 6];
            size_t pos = offset + v6FixedHeader;
            // Walk extension headers until we reach a non-extension protocol.
            while (true) {
                uint8_t newNext = nextHeader;
                if (!walkV6Extension(nextHeader, buffer, packetEnd, pos, newNext)) break;
                nextHeader = newNext;
            }
            l4Proto = nextHeader;
            l4Offset = pos;
        } else {
            parsed.protocol = "Non-IP";
            return parsed;
        }

        // 4. Layer 4.
        if (l4Proto == 6) { // TCP
            parsed.protocol = "TCP";
            if (packetEnd < l4Offset + sizeof(TCPHeader)) return parsed;
            parsed.srcPort = readU16(buffer + l4Offset);
            parsed.dstPort = readU16(buffer + l4Offset + 2);

            const size_t tcpHeaderLen = (buffer[l4Offset + 12] >> 4) * 4;
            if (tcpHeaderLen < sizeof(TCPHeader) || packetEnd < l4Offset + tcpHeaderLen) return parsed;
            const size_t payloadOffset = l4Offset + tcpHeaderLen;
            if (payloadOffset < packetEnd) {
                if (parsed.dstPort == 443 || parsed.srcPort == 443) {
                    parseTLS(buffer + payloadOffset, packetEnd - payloadOffset, parsed);
                }
            }
            // Port-based service hint when SNI didn't fire.
            if (parsed.service.empty()) {
                switch (parsed.dstPort == 0 ? parsed.srcPort : parsed.dstPort) {
                    case 22:   parsed.service = "SSH"; break;
                    case 23:   parsed.service = "Telnet"; break;
                    case 25:   parsed.service = "SMTP"; break;
                    case 80:   parsed.service = "HTTP"; break;
                    case 110:  parsed.service = "POP3"; break;
                    case 143:  parsed.service = "IMAP"; break;
                    case 465:
                    case 587:  parsed.service = "SMTP+TLS"; break;
                    case 993:  parsed.service = "IMAP+TLS"; break;
                    case 995:  parsed.service = "POP3+TLS"; break;
                    case 1883: parsed.service = "MQTT"; break;
                    case 3389: parsed.service = "RDP"; break;
                    case 5222: parsed.service = "XMPP"; break;
                    default: break;
                }
            }
        } else if (l4Proto == 17) { // UDP
            parsed.protocol = "UDP";
            if (packetEnd < l4Offset + sizeof(UDPHeader)) return parsed;
            parsed.srcPort = readU16(buffer + l4Offset);
            parsed.dstPort = readU16(buffer + l4Offset + 2);
            if (parsed.service.empty()) {
                const uint16_t port = parsed.dstPort == 0 ? parsed.srcPort : parsed.dstPort;
                switch (port) {
                    case 53:    parsed.service = "DNS"; break;
                    case 67:
                    case 68:    parsed.service = "DHCP"; break;
                    case 123:   parsed.service = "NTP"; break;
                    case 161:
                    case 162:   parsed.service = "SNMP"; break;
                    case 443:   parsed.service = "QUIC"; break;
                    case 500:
                    case 4500:  parsed.service = "IPsec"; break;
                    case 1900:  parsed.service = "SSDP"; break;
                    case 5353:  parsed.service = "mDNS"; break;
                    case 5355:  parsed.service = "LLMNR"; break;
                    case 137:
                    case 138:
                    case 139:   parsed.service = "NetBIOS"; break;
                    case 3478:
                    case 3479:
                    case 5349:  parsed.service = "STUN/TURN"; break;
                    default: break;
                }
            }
            // QUIC ClientHello SNI: only client → server Initial packets (dst
            // port 443) carry the ClientHello. The Long Header bit + Fixed bit
            // (0xC0 mask) is a cheap pre-filter before the expensive crypto.
            if (parsed.dstPort == 443 && packetEnd > l4Offset + sizeof(UDPHeader)) {
                const uint8_t* udpPayload = buffer + l4Offset + sizeof(UDPHeader);
                const size_t udpPayloadLen = packetEnd - (l4Offset + sizeof(UDPHeader));
                if (udpPayloadLen >= 1 && (udpPayload[0] & 0xC0) == 0xC0) {
                    if (auto sni = QuicParser::extractInitialSni(udpPayload, udpPayloadLen)) {
                        parsed.sni = *sni;
                    }
                }
            }
        } else if (l4Proto == 1) { // ICMPv4
            parsed.protocol = "ICMP";
            if (packetEnd >= l4Offset + 2) {
                const uint8_t type = buffer[l4Offset];
                const uint8_t code = buffer[l4Offset + 1];
                switch (type) {
                    case 0:  parsed.service = "Echo reply"; break;
                    case 8:  parsed.service = "Echo request"; break;
                    case 3:  parsed.service = "Destination unreachable"; break;
                    case 11: parsed.service = "Time exceeded"; break;
                    case 5:  parsed.service = "Redirect"; break;
                    default: parsed.service = "ICMP type " + std::to_string(type); break;
                }
                (void)code;
            }
        } else if (l4Proto == 58) { // ICMPv6
            parsed.protocol = "ICMPv6";
            if (packetEnd >= l4Offset + 2) {
                const uint8_t type = buffer[l4Offset];
                switch (type) {
                    case 128: parsed.service = "Echo request"; break;
                    case 129: parsed.service = "Echo reply"; break;
                    case 133: parsed.service = "Router solicitation"; break;
                    case 134: parsed.service = "Router advertisement"; break;
                    case 135: parsed.service = "Neighbor solicitation"; break;
                    case 136: parsed.service = "Neighbor advertisement"; break;
                    case 1:   parsed.service = "Destination unreachable"; break;
                    case 3:   parsed.service = "Time exceeded"; break;
                    default:  parsed.service = "ICMPv6 type " + std::to_string(type); break;
                }
            }
        } else if (const char* name = ipProtocolName(l4Proto); name != nullptr) {
            parsed.protocol = name;
        } else {
            parsed.protocol = "IP proto " + std::to_string(l4Proto);
        }

        return parsed;
    }

    std::string ProtocolParser::ipToString(uint32_t ip) {
        char address[INET_ADDRSTRLEN]{};
        return inet_ntop(AF_INET, &ip, address, sizeof(address)) ? address : "";
    }

    void ProtocolParser::parseTLS(const uint8_t* payload, size_t len, ParsedPacket& outPacket) {
        constexpr size_t recordHeaderLength = 5;
        constexpr size_t handshakeHeaderLength = 4;
        constexpr size_t clientHelloFixedLength = 34; // Version + random

        if (len < recordHeaderLength || payload[0] != 0x16) return; // TLS handshake record

        const size_t recordEnd = std::min(len, recordHeaderLength + static_cast<size_t>(readU16(payload + 3)));
        size_t pos = recordHeaderLength;
        if (recordEnd < pos + handshakeHeaderLength || payload[pos] != 0x01) return; // ClientHello

        const size_t handshakeLength = (static_cast<size_t>(payload[pos + 1]) << 16)
            | (static_cast<size_t>(payload[pos + 2]) << 8) | payload[pos + 3];
        pos += handshakeHeaderLength;
        const size_t handshakeEnd = std::min(recordEnd, pos + handshakeLength);
        if (handshakeEnd < pos + clientHelloFixedLength) return;
        pos += clientHelloFixedLength;

        if (pos >= handshakeEnd) return;
        const size_t sessionIdLength = payload[pos++];
        if (sessionIdLength > handshakeEnd - pos) return;
        pos += sessionIdLength;

        if (handshakeEnd - pos < 2) return;
        const size_t cipherSuitesLength = readU16(payload + pos);
        pos += 2;
        if (cipherSuitesLength > handshakeEnd - pos) return;
        pos += cipherSuitesLength;

        if (pos >= handshakeEnd) return;
        const size_t compressionMethodsLength = payload[pos++];
        if (compressionMethodsLength > handshakeEnd - pos) return;
        pos += compressionMethodsLength;

        if (handshakeEnd - pos < 2) return;
        const size_t extensionsLength = readU16(payload + pos);
        pos += 2;
        if (extensionsLength > handshakeEnd - pos) return;
        const size_t extensionsEnd = pos + extensionsLength;

        while (extensionsEnd - pos >= 4) {
            const uint16_t extensionType = readU16(payload + pos);
            const size_t extensionLength = readU16(payload + pos + 2);
            pos += 4;
            if (extensionLength > extensionsEnd - pos) return;
            const size_t extensionEnd = pos + extensionLength;

            if (extensionType == 0x0000) { // Server Name Indication
                if (extensionEnd - pos < 2) return;
                const size_t nameListLength = readU16(payload + pos);
                pos += 2;
                if (nameListLength > extensionEnd - pos) return;
                const size_t nameListEnd = pos + nameListLength;

                while (nameListEnd - pos >= 3) {
                    const uint8_t nameType = payload[pos++];
                    const size_t nameLength = readU16(payload + pos);
                    pos += 2;
                    if (nameLength > nameListEnd - pos) return;
                    if (nameType == 0x00) {
                        outPacket.sni = std::string(reinterpret_cast<const char*>(payload + pos), nameLength);
                        outPacket.service = identifyService(outPacket.sni);
                        return;
                    }
                    pos += nameLength;
                }
                return;
            }

            pos = extensionEnd;
        }
    }

    std::string ProtocolParser::identifyService(const std::string& sni) {
        // Substring match against a curated catalog of major services.
        // The map is ordered by specificity — more specific patterns first.
        struct Pattern { std::string_view needle; std::string_view label; };
        static constexpr std::array catalog = std::to_array<Pattern>({
            // Google ecosystem
            {"youtube",         "YouTube"},
            {"googlevideo",     "YouTube"},
            {"ytimg",           "YouTube"},
            {"gstatic",         "Google"},
            {"googleusercontent","Google"},
            {"googleapis",      "Google"},
            {"google.",         "Google"},
            {"doubleclick",     "Google Ads"},

            // Streaming / video
            {"netflix",         "Netflix"},
            {"nflxvideo",       "Netflix"},
            {"twitch",          "Twitch"},
            {"ttvnw",           "Twitch"},
            {"spotify",         "Spotify"},
            {"scdn.co",         "Spotify"},
            {"hulu",            "Hulu"},
            {"disney",          "Disney+"},
            {"primevideo",      "Prime Video"},

            // Social / messaging
            {"discord",         "Discord"},
            {"discordapp",      "Discord"},
            {"slack.com",       "Slack"},
            {"slack-edge",      "Slack"},
            {"telegram",        "Telegram"},
            {"whatsapp",        "WhatsApp"},
            {"facebook",        "Facebook"},
            {"fbcdn",           "Facebook"},
            {"instagram",       "Instagram"},
            {"cdninstagram",    "Instagram"},
            {"twitter",         "X (Twitter)"},
            {"twimg",           "X (Twitter)"},
            {"x.com",           "X (Twitter)"},
            {"tiktok",          "TikTok"},
            {"tiktokcdn",       "TikTok"},
            {"reddit",          "Reddit"},
            {"redditstatic",    "Reddit"},
            {"linkedin",        "LinkedIn"},
            {"signal.org",      "Signal"},

            // Dev / cloud
            {"github",          "GitHub"},
            {"githubusercontent","GitHub"},
            {"gitlab",          "GitLab"},
            {"bitbucket",       "Bitbucket"},
            {"npmjs",           "npm"},
            {"jsdelivr",        "jsDelivr"},
            {"cloudflare",      "Cloudflare"},
            {"akamai",          "Akamai"},
            {"fastly",          "Fastly"},
            {"amazonaws",       "AWS"},
            {"awsstatic",       "AWS"},
            {"azureedge",       "Azure"},
            {"windows.net",     "Azure"},
            {"azure.com",       "Azure"},
            {"digitalocean",    "DigitalOcean"},
            {"vercel",          "Vercel"},
            {"netlify",         "Netlify"},

            // Microsoft
            {"microsoft",       "Microsoft"},
            {"msftncsi",        "Microsoft"},
            {"office.com",      "Microsoft 365"},
            {"office365",       "Microsoft 365"},
            {"outlook",         "Outlook"},
            {"live.com",        "Microsoft"},
            {"bing.com",        "Bing"},
            {"xboxlive",        "Xbox Live"},
            {"xbox.com",        "Xbox Live"},
            {"skype",           "Skype"},
            {"teams.microsoft", "Microsoft Teams"},

            // Apple
            {"apple.com",       "Apple"},
            {"icloud",          "iCloud"},
            {"itunes.apple",    "iTunes"},
            {"mzstatic",        "Apple"},

            // Gaming
            {"steampowered",    "Steam"},
            {"steamstatic",     "Steam"},
            {"steamcommunity",  "Steam"},
            {"epicgames",       "Epic Games"},
            {"riotgames",       "Riot Games"},
            {"battle.net",      "Battle.net"},
            {"playstation",     "PlayStation"},
            {"nintendo",        "Nintendo"},

            // Shopping
            {"amazon",          "Amazon"},
            {"ebay",            "eBay"},
            {"shopify",         "Shopify"},

            // Communication / video
            {"zoom.us",         "Zoom"},
            {"zoomgov",         "Zoom"},
            {"webex",           "Webex"},
            {"meet.google",     "Google Meet"},

            // News / misc
            {"wikipedia",       "Wikipedia"},
            {"wikimedia",       "Wikipedia"},

            // Mozilla / privacy
            {"mozilla",         "Mozilla"},
            {"firefox",         "Firefox"},
            {"duckduckgo",      "DuckDuckGo"},
            {"protonmail",      "Proton"},
            {"proton.me",       "Proton"},
        });

        const std::string lower = toLowerCopy(sni);
        for (const auto& pat : catalog) {
            if (lower.find(pat.needle) != std::string::npos) return std::string(pat.label);
        }
        return {};
    }

} // namespace core
