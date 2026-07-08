#include "core/ProtocolParser.hpp"
#include "core/NetworkPlatform.hpp"
#include "core/QuicParser.hpp"
#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <string_view>

namespace core {
    namespace {
        constexpr uint16_t kEthIPv4    = 0x0800;
        constexpr uint16_t kEthARP     = 0x0806;
        constexpr uint16_t kEthIPv6    = 0x86DD;

        uint16_t readU16(const uint8_t* bytes) {
            return static_cast<uint16_t>(bytes[0]) << 8 | bytes[1];
        }

        uint32_t readU32(const uint8_t* bytes) {
            return (static_cast<uint32_t>(bytes[0]) << 24)
                 | (static_cast<uint32_t>(bytes[1]) << 16)
                 | (static_cast<uint32_t>(bytes[2]) << 8)
                 |  static_cast<uint32_t>(bytes[3]);
        }

        std::string ipv4ToString(const uint8_t* bytes) {
            uint32_t address;
            std::memcpy(&address, bytes, sizeof(address));
            char addrStr[INET_ADDRSTRLEN]{};
            return inet_ntop(AF_INET, &address, addrStr, sizeof(addrStr)) ? addrStr : "";
        }

        std::string ipv6ToString(const uint8_t* bytes) {
            char addrStr[INET6_ADDRSTRLEN]{};
            return inet_ntop(AF_INET6, bytes, addrStr, sizeof(addrStr)) ? addrStr : "";
        }

        bool walkV6Extension(uint8_t nextHeader, const uint8_t* buffer, size_t size, size_t& pos, uint8_t& outNext) {
            if (nextHeader == 0 || nextHeader == 43 || nextHeader == 60 || nextHeader == 51) {
                if (size < pos + 2) return false;
                outNext = buffer[pos];
                const size_t extLen = (nextHeader == 51)
                    ? (static_cast<size_t>(buffer[pos + 1]) + 2) * 4
                    : (static_cast<size_t>(buffer[pos + 1]) + 1) * 8;
                if (size < pos + extLen) return false;
                pos += extLen;
                return true;
            }
            return false;
        }

        std::string toLowerCopy(std::string_view sv) {
            std::string out(sv);
            std::transform(out.begin(), out.end(), out.begin(),
                [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
            return out;
        }

        bool decodeLinkLayer(const uint8_t* buffer, size_t size, LinkType link,
                             size_t& outOffset, uint16_t& outEtherType) {
            const auto etherTypeForIpVersion = [&](size_t at) -> bool {
                if (at >= size) return false;
                const uint8_t version = buffer[at] >> 4;
                if (version == 4) { outEtherType = kEthIPv4; return true; }
                if (version == 6) { outEtherType = kEthIPv6; return true; }
                return false;
            };

            switch (link) {
            case LinkType::Ethernet: {
                if (size < sizeof(EthernetHeader)) return false;
                outOffset = sizeof(EthernetHeader);
                outEtherType = readU16(buffer + 12);
                while (outEtherType == 0x8100 || outEtherType == 0x88A8 || outEtherType == 0x9100) {
                    if (size < outOffset + 4) return false;
                    outEtherType = readU16(buffer + outOffset + 2);
                    outOffset += 4;
                }
                return true;
            }
            case LinkType::LinuxSLL: {
                if (size < 16) return false;
                outOffset = 16;
                outEtherType = readU16(buffer + 14);
                return true;
            }
            case LinkType::LinuxSLL2: {
                if (size < 20) return false;
                outOffset = 20;
                outEtherType = readU16(buffer);
                return true;
            }
            case LinkType::NullLoopback: {
                if (size < 4) return false;
                outOffset = 4;
                const uint32_t le = static_cast<uint32_t>(buffer[0])
                    | (static_cast<uint32_t>(buffer[1]) << 8)
                    | (static_cast<uint32_t>(buffer[2]) << 16)
                    | (static_cast<uint32_t>(buffer[3]) << 24);
                const uint32_t be = readU32(buffer);
                for (uint32_t af : {le, be}) {
                    if (af == 2)  { outEtherType = kEthIPv4; return true; }
                    if (af == 10 || af == 23 || af == 24 || af == 28 || af == 30) {
                        outEtherType = kEthIPv6;
                        return true;
                    }
                }
                return etherTypeForIpVersion(4);
            }
            case LinkType::Loop: {
                if (size < 4) return false;
                outOffset = 4;
                const uint32_t af = readU32(buffer);
                if (af == 2)  { outEtherType = kEthIPv4; return true; }
                if (af == 10 || af == 23 || af == 24 || af == 28 || af == 30) {
                    outEtherType = kEthIPv6;
                    return true;
                }
                return etherTypeForIpVersion(4);
            }
            case LinkType::RawIP:
                outOffset = 0;
                return etherTypeForIpVersion(0);
            case LinkType::IPv4:
                outOffset = 0;
                outEtherType = kEthIPv4;
                return true;
            case LinkType::IPv6:
                outOffset = 0;
                outEtherType = kEthIPv6;
                return true;
            case LinkType::Unsupported:
                return false;
            }
            return false;
        }

        void decodeNetwork(const uint8_t* buffer, size_t end, size_t offset,
                           uint16_t etherType, ParsedPacket& p, int depth);

        void decodeTcp(const uint8_t* buffer, size_t end, size_t offset, ParsedPacket& p) {
            p.protocol = "TCP";
            if (end < offset + sizeof(TCPHeader)) return;
            p.srcPort = readU16(buffer + offset);
            p.dstPort = readU16(buffer + offset + 2);
            p.tcpSeq  = readU32(buffer + offset + 4);

            const uint8_t tcpFlags = buffer[offset + 13];
            p.tcpFin = (tcpFlags & 0x01) != 0;
            p.tcpSyn = (tcpFlags & 0x02) != 0;
            p.tcpRst = (tcpFlags & 0x04) != 0;
            p.tcpAck = (tcpFlags & 0x10) != 0;

            const size_t tcpHeaderLen = (buffer[offset + 12] >> 4) * 4;
            if (tcpHeaderLen < sizeof(TCPHeader) || end < offset + tcpHeaderLen) return;

            const size_t payloadOffset = offset + tcpHeaderLen;
            if (payloadOffset < end) {
                p.payloadOffset = payloadOffset;
                p.payloadLength = end - payloadOffset;
            }
        }

        void decodeUdp(const uint8_t* buffer, size_t end, size_t offset,
                       ParsedPacket& p, int depth) {
            p.protocol = "UDP";
            if (end < offset + sizeof(UDPHeader)) return;
            p.srcPort = readU16(buffer + offset);
            p.dstPort = readU16(buffer + offset + 2);

            const uint16_t udpLength = readU16(buffer + offset + 4);
            const size_t declaredEnd = udpLength >= sizeof(UDPHeader)
                ? offset + udpLength
                : end;
            const size_t udpEnd = std::min(end, declaredEnd);
            const size_t payloadOffset = offset + sizeof(UDPHeader);
            if (payloadOffset >= udpEnd) return;

            p.payloadOffset = payloadOffset;
            p.payloadLength = udpEnd - payloadOffset;
        }

        void decodeIcmp(const uint8_t* buffer, size_t end, size_t offset, ParsedPacket& p) {
            p.protocol = "ICMP";
            if (end < offset + 2) return;
            switch (buffer[offset]) {
                case 0:  p.service = "Echo reply"; break;
                case 8:  p.service = "Echo request"; break;
                case 3:  p.service = "Destination unreachable"; break;
                case 11: p.service = "Time exceeded"; break;
                case 5:  p.service = "Redirect"; break;
                default: p.service = "ICMP type " + std::to_string(buffer[offset]); break;
            }
        }

        void decodeIcmpv6(const uint8_t* buffer, size_t end, size_t offset, ParsedPacket& p) {
            p.protocol = "ICMPv6";
            if (end < offset + 2) return;
            switch (buffer[offset]) {
                case 128: p.service = "Echo request"; break;
                case 129: p.service = "Echo reply"; break;
                case 133: p.service = "Router solicitation"; break;
                case 134: p.service = "Router advertisement"; break;
                case 135: p.service = "Neighbor solicitation"; break;
                case 136: p.service = "Neighbor advertisement"; break;
                case 1:   p.service = "Destination unreachable"; break;
                case 3:   p.service = "Time exceeded"; break;
                default:  p.service = "ICMPv6 type " + std::to_string(buffer[offset]); break;
            }
        }

        const char* ipProtocolName(uint8_t proto) {
            switch (proto) {
                case 2:   return "IGMP";
                case 50:  return "ESP";
                case 51:  return "AH";
                case 89:  return "OSPF";
                case 132: return "SCTP";
                default:  return nullptr;
            }
        }

        void decodeTransport(const uint8_t* buffer, size_t end, size_t offset,
                             uint8_t l4Proto, ParsedPacket& p, int depth) {
            switch (l4Proto) {
            case 6:  decodeTcp(buffer, end, offset, p); return;
            case 17: decodeUdp(buffer, end, offset, p, depth); return;
            case 1:  decodeIcmp(buffer, end, offset, p); return;
            case 58: decodeIcmpv6(buffer, end, offset, p); return;
            default: break;
            }

            if (const char* name = ipProtocolName(l4Proto)) {
                p.protocol = name;
            } else {
                p.protocol = "IP proto " + std::to_string(l4Proto);
            }
        }

        void decodeNetwork(const uint8_t* buffer, size_t end, size_t offset,
                           uint16_t etherType, ParsedPacket& p, int depth) {
            if (etherType == kEthIPv4) {
                if (end < offset + sizeof(IPv4Header)) return;
                const uint8_t versionHlen = buffer[offset];
                const size_t ihl = (versionHlen & 0x0F) * 4;
                if ((versionHlen >> 4) != 4 || ihl < sizeof(IPv4Header) || end < offset + ihl) return;

                const uint16_t totalLength = readU16(buffer + offset + 2);
                if (totalLength < ihl) return;
                const size_t packetEnd = std::min(end, offset + static_cast<size_t>(totalLength));

                p.srcIP = ipv4ToString(buffer + offset + 12);
                p.dstIP = ipv4ToString(buffer + offset + 16);

                const uint16_t flagsFragOff = readU16(buffer + offset + 6);
                if ((flagsFragOff & 0x1FFF) != 0) {
                    p.protocol = "IPv4 Fragment";
                    return;
                }
                decodeTransport(buffer, packetEnd, offset + ihl, buffer[offset + 9], p, depth);
                return;
            }

            if (etherType == kEthIPv6) {
                constexpr size_t v6FixedHeader = 40;
                if (end < offset + v6FixedHeader) return;
                const uint16_t payloadLen = readU16(buffer + offset + 4);
                const size_t packetEnd = std::min(end, offset + v6FixedHeader + static_cast<size_t>(payloadLen));

                p.srcIP = ipv6ToString(buffer + offset + 8);
                p.dstIP = ipv6ToString(buffer + offset + 24);

                uint8_t nextHeader = buffer[offset + 6];
                size_t pos = offset + v6FixedHeader;
                while (true) {
                    uint8_t newNext = nextHeader;
                    if (!walkV6Extension(nextHeader, buffer, packetEnd, pos, newNext)) break;
                    nextHeader = newNext;
                }
                decodeTransport(buffer, packetEnd, pos, nextHeader, p, depth);
                return;
            }

            if (etherType == kEthARP) {
                p.protocol = "ARP";
                if (end < offset + 8) return;
                const uint16_t ptype = readU16(buffer + offset + 2);
                const uint8_t hlen = buffer[offset + 4];
                const uint8_t plen = buffer[offset + 5];
                const uint16_t oper = readU16(buffer + offset + 6);
                const size_t arpBody = offset + 8;
                if (ptype == kEthIPv4 && plen == 4 && end >= arpBody + 2u * (hlen + plen)) {
                    p.srcIP = ipv4ToString(buffer + arpBody + hlen);
                    p.dstIP = ipv4ToString(buffer + arpBody + 2u * hlen + plen);
                }
                p.service = (oper == 1) ? "ARP request" : (oper == 2) ? "ARP reply" : "";
                return;
            }
            p.protocol = "Non-IP";
        }

        void classifyTcpPort(uint16_t port, ParsedPacket& p) {
            if (!p.service.empty()) return;
            switch (port) {
                case 22:    p.service = "SSH"; break;
                case 23:    p.service = "Telnet"; break;
                case 25:    p.service = "SMTP"; break;
                case 80:    p.service = "HTTP"; break;
                case 110:   p.service = "POP3"; break;
                case 143:   p.service = "IMAP"; break;
                case 465:
                case 587:   p.service = "SMTP+TLS"; break;
                case 993:   p.service = "IMAP+TLS"; break;
                case 995:   p.service = "POP3+TLS"; break;
                case 1883:  p.service = "MQTT"; break;
                case 3389:  p.service = "RDP"; break;
                case 5222:  p.service = "XMPP"; break;
                default: break;
            }
        }

        void classifyUdpPort(uint16_t port, ParsedPacket& p) {
            if (!p.service.empty()) return;
            switch (port) {
                case 53:    p.service = "DNS"; break;
                case 67:
                case 68:    p.service = "DHCP"; break;
                case 123:   p.service = "NTP"; break;
                case 137:
                case 138:
                case 139:   p.service = "NetBIOS"; break;
                case 161:
                case 162:   p.service = "SNMP"; break;
                case 443:   p.service = "QUIC"; break;
                case 500:
                case 4500:  p.service = "IPsec"; break;
                case 1900:  p.service = "SSDP"; break;
                case 5353:  p.service = "mDNS"; break;
                case 5355:  p.service = "LLMNR"; break;
                case 3478:
                case 3479:
                case 5349:  p.service = "STUN/TURN"; break;
                default: break;
            }
        }

    } // namespace

    void ProtocolParser::parseTLS(const uint8_t* payload, size_t len, ParsedPacket& outPacket) {
        constexpr size_t recordHeaderLength = 5;
        constexpr size_t handshakeHeaderLength = 4;
        constexpr size_t clientHelloFixedLength = 34;

        if (len < recordHeaderLength || payload[0] != 0x16) return;

        const size_t recordEnd = std::min(len, recordHeaderLength + static_cast<size_t>(readU16(payload + 3)));
        size_t pos = recordHeaderLength;
        if (recordEnd < pos + handshakeHeaderLength || payload[pos] != 0x01) return;

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

            if (extensionType == 0x0000) {
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
        struct Pattern { std::string_view needle; std::string_view label; };
        static constexpr std::array catalog = std::to_array<Pattern>({
            {"youtube",         "YouTube"},
            {"googlevideo",     "YouTube"},
            {"ytimg",           "YouTube"},
            {"gstatic",         "Google"},
            {"googleusercontent","Google"},
            {"googleapis",      "Google"},
            {"google.",         "Google"},
            {"doubleclick",     "Google Ads"},
            {"netflix",         "Netflix"},
            {"nflxvideo",       "Netflix"},
            {"twitch",          "Twitch"},
            {"ttvnw",           "Twitch"},
            {"spotify",         "Spotify"},
            {"scdn.co",         "Spotify"},
            {"hulu",            "Hulu"},
            {"disney",          "Disney+"},
            {"primevideo",      "Prime Video"},
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
            {"apple.com",       "Apple"},
            {"icloud",          "iCloud"},
            {"itunes.apple",    "iTunes"},
            {"mzstatic",        "Apple"},
            {"steampowered",    "Steam"},
            {"steamstatic",     "Steam"},
            {"steamcommunity",  "Steam"},
            {"epicgames",       "Epic Games"},
            {"riotgames",       "Riot Games"},
            {"battle.net",      "Battle.net"},
            {"playstation",     "PlayStation"},
            {"nintendo",        "Nintendo"},
            {"amazon",          "Amazon"},
            {"ebay",            "eBay"},
            {"shopify",         "Shopify"},
            {"zoom.us",         "Zoom"},
            {"zoomgov",         "Zoom"},
            {"webex",           "Webex"},
            {"meet.google",     "Google Meet"},
            {"wikipedia",       "Wikipedia"},
            {"wikimedia",       "Wikipedia"},
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

    ParsedPacket ProtocolParser::parse(const PacketData& rawData) {
        ParsedPacket parsed;
        parsed.timestamp = rawData.timestamp;

        const uint8_t* buffer = rawData.payload.data();
        const size_t size = rawData.payload.size();
        if (buffer == nullptr || size == 0) return parsed;

        size_t offset = 0;
        uint16_t etherType = 0;
        if (!decodeLinkLayer(buffer, size, rawData.linkType, offset, etherType)) {
            parsed.protocol = rawData.linkType == LinkType::Unsupported
                ? "Unsupported link type"
                : "Truncated";
            return parsed;
        }

        decodeNetwork(buffer, size, offset, etherType, parsed, 0);

        if (parsed.payloadLength > 0 && parsed.payloadOffset < size) {
            const uint8_t* payload = buffer + parsed.payloadOffset;
            const size_t payloadLen = std::min(parsed.payloadLength, size - parsed.payloadOffset);

            if (parsed.protocol == "TCP") {
                if (payloadLen >= 5 && payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x04) {
                    parseTLS(payload, payloadLen, parsed);
                }
                classifyTcpPort(parsed.dstPort, parsed);
                classifyTcpPort(parsed.srcPort, parsed);
            } else if (parsed.protocol == "UDP") {
                if (parsed.dstPort == 443 && payloadLen >= 1 && (payload[0] & 0xC0) == 0xC0) {
                    if (auto sni = QuicParser::extractInitialSni(payload, payloadLen)) {
                        parsed.sni = *sni;
                        parsed.service = identifyService(*sni);
                    }
                    if (parsed.service.empty()) parsed.service = "QUIC";
                }
                classifyUdpPort(parsed.dstPort, parsed);
                classifyUdpPort(parsed.srcPort, parsed);
            }
        } else if (parsed.protocol == "TCP") {
            classifyTcpPort(parsed.dstPort, parsed);
            classifyTcpPort(parsed.srcPort, parsed);
        } else if (parsed.protocol == "UDP") {
            classifyUdpPort(parsed.dstPort, parsed);
            classifyUdpPort(parsed.srcPort, parsed);
        }

        return parsed;
    }

} // namespace core
