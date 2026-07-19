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

        constexpr uint16_t kEthIPv4    = 0x0800;
        constexpr uint16_t kEthARP     = 0x0806;
        constexpr uint16_t kEthIPv6    = 0x86DD;
        constexpr uint16_t kEthMplsUni = 0x8847;
        constexpr uint16_t kEthMplsMul = 0x8848;
        constexpr uint16_t kEthPppoeSess = 0x8864;
        constexpr uint16_t kEthTrBridge  = 0x6558; // Transparent Ethernet Bridging (GENEVE/GRE)

        // Descending through more than a few layers of encapsulation means
        // either an exotic capture or a malicious packet trying to make us spin.
        constexpr int kMaxTunnelDepth = 4;

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
            char buf[INET_ADDRSTRLEN]{};
            return inet_ntop(AF_INET, &address, buf, sizeof(buf)) ? buf : "";
        }

        std::string ipv6ToString(const uint8_t* bytes) {
            char buf[INET6_ADDRSTRLEN]{};
            return inet_ntop(AF_INET6, bytes, buf, sizeof(buf)) ? buf : "";
        }

        // Map an L4 (or "next header") protocol number to a short label.
        // Returns nullptr for protocols the caller decodes itself (TCP / UDP /
        // ICMP / tunnels).
        const char* ipProtocolName(uint8_t proto) {
            switch (proto) {
                case 2:   return "IGMP";
                case 33:  return "DCCP";
                case 50:  return "ESP";
                case 51:  return "AH";
                case 89:  return "OSPF";
                case 103: return "PIM";
                case 112: return "VRRP";
                case 132: return "SCTP";
                default:  return nullptr;
            }
        }

        // Frames that never carry IP. Naming them beats a bare "Non-IP" bucket,
        // since these are constant background noise on any real LAN.
        const char* etherTypeName(uint16_t etherType) {
            switch (etherType) {
                case 0x88CC: return "LLDP";
                case 0x888E: return "EAPOL";
                case 0x8863: return "PPPoE Discovery";
                case 0x8100:
                case 0x88A8:
                case 0x9100: return "VLAN";
                case 0x8137: return "IPX";
                case 0x88F7: return "PTP";
                case 0x22EA: return "SRP";
                case 0x8035: return "RARP";
                case 0x9000: return "Ethernet Loopback";
                case 0x88A4: return "EtherCAT";
                case 0x8892: return "PROFINET";
                default:     return nullptr;
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
                case 51: // Authentication Header. Integrity-only, so the payload
                         // behind it is still readable — walk straight through.
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

        // Record a layer of encapsulation. The first call also snapshots the
        // carrier addresses so the UI can still show who was tunnelling.
        void pushTunnel(ParsedPacket& p, const char* name) {
            if (p.outerSrcIP.empty() && !p.srcIP.empty()) {
                p.outerSrcIP = p.srcIP;
                p.outerDstIP = p.dstIP;
            }
            if (p.tunnel.empty()) p.tunnel = name;
            else                  p.tunnel += std::string("/") + name;
        }

        // Resolve the start of the network layer for a given link encapsulation.
        // Returns false when the header is truncated or the link type carries no
        // IP payload we can locate. `outEtherType` is synthesized for link types
        // that do not carry a real EtherType (raw IP, loopback).
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
                // 802.1Q / QinQ tags stack ahead of the real EtherType.
                while (outEtherType == 0x8100 || outEtherType == 0x88A8 || outEtherType == 0x9100) {
                    if (size < outOffset + 4) return false;
                    outEtherType = readU16(buffer + outOffset + 2);
                    outOffset += 4;
                }
                return true;
            }
            case LinkType::LinuxSLL: {
                // 16-byte cooked header; EtherType is the last field.
                if (size < 16) return false;
                outOffset = 16;
                outEtherType = readU16(buffer + 14);
                return true;
            }
            case LinkType::LinuxSLL2: {
                // 20-byte cooked v2 header; EtherType comes first.
                if (size < 20) return false;
                outOffset = 20;
                outEtherType = readU16(buffer);
                return true;
            }
            case LinkType::NullLoopback: {
                // 4-byte address family in the *writing host's* byte order, so
                // try both before giving up. AF_INET is 2 everywhere; AF_INET6
                // differs across the BSDs (24/28/30) and Linux (10).
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
                // Unknown AF — fall back to sniffing the IP version nibble.
                return etherTypeForIpVersion(4);
            }
            case LinkType::Loop: {
                if (size < 4) return false;
                outOffset = 4;
                const uint32_t af = readU32(buffer); // always big-endian
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

        // Forward declaration: the tunnel decoders recurse back into the network
        // layer for the encapsulated packet.
        void decodeNetwork(const uint8_t* buffer, size_t end, size_t offset,
                           uint16_t etherType, ParsedPacket& p, int depth);

        // Re-enter at an inner Ethernet frame (VXLAN, GENEVE with TEB, GRE-TEB).
        void decodeInnerEthernet(const uint8_t* buffer, size_t end, size_t offset,
                                 ParsedPacket& p, int depth) {
            size_t innerOffset = 0;
            uint16_t innerEtherType = 0;
            if (offset >= end) return;
            if (!decodeLinkLayer(buffer + offset, end - offset, LinkType::Ethernet,
                                 innerOffset, innerEtherType)) {
                return;
            }
            decodeNetwork(buffer, end, offset + innerOffset, innerEtherType, p, depth + 1);
        }

        // GRE (RFC 2784 + key/sequence extensions). Only version 0 carries a
        // plain encapsulated protocol; version 1 is PPTP and its payload is a
        // PPP frame we do not decode.
        void decodeGre(const uint8_t* buffer, size_t end, size_t offset,
                       ParsedPacket& p, int depth) {
            if (end < offset + 4) return;
            const uint16_t flags = readU16(buffer + offset);
            const uint16_t innerType = readU16(buffer + offset + 2);
            if ((flags & 0x0007) != 0) return; // not version 0

            size_t headerLen = 4;
            if (flags & 0x8000) headerLen += 4; // checksum + reserved1
            if (flags & 0x2000) headerLen += 4; // key
            if (flags & 0x1000) headerLen += 4; // sequence
            if (end < offset + headerLen) return;

            pushTunnel(p, "GRE");
            const size_t innerOffset = offset + headerLen;
            if (innerType == kEthTrBridge) {
                decodeInnerEthernet(buffer, end, innerOffset, p, depth);
            } else if (innerType == kEthIPv4 || innerType == kEthIPv6) {
                decodeNetwork(buffer, end, innerOffset, innerType, p, depth + 1);
            }
        }

        // VXLAN (RFC 7348): 8-byte header, then a complete inner Ethernet frame.
        void decodeVxlan(const uint8_t* buffer, size_t end, size_t offset,
                         ParsedPacket& p, int depth) {
            constexpr size_t vxlanHeader = 8;
            if (end < offset + vxlanHeader) return;
            if ((buffer[offset] & 0x08) == 0) return; // 'I' flag must be set
            pushTunnel(p, "VXLAN");
            decodeInnerEthernet(buffer, end, offset + vxlanHeader, p, depth);
        }

        // GENEVE (RFC 8926): 8-byte base header plus variable options, then a
        // frame identified by the protocol_type EtherType.
        void decodeGeneve(const uint8_t* buffer, size_t end, size_t offset,
                          ParsedPacket& p, int depth) {
            constexpr size_t geneveBase = 8;
            if (end < offset + geneveBase) return;
            const uint8_t verOptLen = buffer[offset];
            if ((verOptLen >> 6) != 0) return; // version must be 0
            const size_t optionsLen = static_cast<size_t>(verOptLen & 0x3F) * 4;
            const uint16_t innerType = readU16(buffer + offset + 2);
            const size_t innerOffset = offset + geneveBase + optionsLen;
            if (end < innerOffset) return;

            pushTunnel(p, "GENEVE");
            if (innerType == kEthTrBridge) {
                decodeInnerEthernet(buffer, end, innerOffset, p, depth);
            } else if (innerType == kEthIPv4 || innerType == kEthIPv6) {
                decodeNetwork(buffer, end, innerOffset, innerType, p, depth + 1);
            }
        }

        // MPLS label stack: 4 bytes per label, bottom-of-stack bit in byte 2.
        // Underneath is bare IP (no EtherType), so sniff the version nibble.
        void decodeMpls(const uint8_t* buffer, size_t end, size_t offset,
                        ParsedPacket& p, int depth) {
            size_t pos = offset;
            for (int label = 0; label < 8; ++label) {
                if (end < pos + 4) return;
                const bool bottomOfStack = (buffer[pos + 2] & 0x01) != 0;
                pos += 4;
                if (!bottomOfStack) continue;

                if (pos >= end) return;
                const uint8_t version = buffer[pos] >> 4;
                if (version != 4 && version != 6) return;
                pushTunnel(p, "MPLS");
                decodeNetwork(buffer, end, pos, version == 4 ? kEthIPv4 : kEthIPv6, p, depth + 1);
                return;
            }
        }

        // PPPoE session stage: 6-byte header, then a 2-byte PPP protocol id.
        void decodePppoe(const uint8_t* buffer, size_t end, size_t offset,
                         ParsedPacket& p, int depth) {
            constexpr size_t pppoeHeader = 6;
            if (end < offset + pppoeHeader + 2) return;
            const uint16_t pppProtocol = readU16(buffer + offset + pppoeHeader);
            const size_t innerOffset = offset + pppoeHeader + 2;
            uint16_t innerType = 0;
            if (pppProtocol == 0x0021)      innerType = kEthIPv4;
            else if (pppProtocol == 0x0057) innerType = kEthIPv6;
            else return;
            pushTunnel(p, "PPPoE");
            decodeNetwork(buffer, end, innerOffset, innerType, p, depth + 1);
        }

        void classifyTcpPort(uint16_t port, ParsedPacket& p);
        void classifyUdpPort(uint16_t port, ParsedPacket& p);

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

            const size_t tcpHeaderLen = static_cast<size_t>(buffer[offset + 12] >> 4) * 4;
            if (tcpHeaderLen < sizeof(TCPHeader) || end < offset + tcpHeaderLen) return;

            // Application-layer DPI happens in parse(), once, on the innermost
            // transport payload — recording where it lives is enough here.
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

            // UDP length bounds the payload, but a truncated capture may cut it
            // short — trust whichever is smaller.
            const uint16_t udpLength = readU16(buffer + offset + 4);
            const size_t declaredEnd = udpLength >= sizeof(UDPHeader)
                ? offset + udpLength
                : end;
            const size_t udpEnd = std::min(end, declaredEnd);
            const size_t payloadOffset = offset + sizeof(UDPHeader);
            if (payloadOffset >= udpEnd) return;

            p.payloadOffset = payloadOffset;
            p.payloadLength = udpEnd - payloadOffset;

            // UDP-borne tunnels carry a whole inner frame; descend before we
            // classify this as ordinary UDP traffic.
            if (depth < kMaxTunnelDepth) {
                if (p.dstPort == 4789 || p.srcPort == 4789) {
                    decodeVxlan(buffer, udpEnd, payloadOffset, p, depth);
                    return;
                }
                if (p.dstPort == 6081 || p.srcPort == 6081) {
                    decodeGeneve(buffer, udpEnd, payloadOffset, p, depth);
                    return;
                }
            }
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

        void decodeTransport(const uint8_t* buffer, size_t end, size_t offset,
                             uint8_t l4Proto, ParsedPacket& p, int depth) {
            switch (l4Proto) {
            case 6:  decodeTcp(buffer, end, offset, p); return;
            case 17: decodeUdp(buffer, end, offset, p, depth); return;
            case 1:  decodeIcmp(buffer, end, offset, p); return;
            case 58: decodeIcmpv6(buffer, end, offset, p); return;

            // Unencrypted IP-in-IP tunnels: the inner packet is right there.
            case 4:
                if (depth < kMaxTunnelDepth) {
                    pushTunnel(p, "IP-in-IP");
                    decodeNetwork(buffer, end, offset, kEthIPv4, p, depth + 1);
                    return;
                }
                break;
            case 41:
                if (depth < kMaxTunnelDepth) {
                    pushTunnel(p, "6in4");
                    decodeNetwork(buffer, end, offset, kEthIPv6, p, depth + 1);
                    return;
                }
                break;
            case 47:
                if (depth < kMaxTunnelDepth) {
                    decodeGre(buffer, end, offset, p, depth);
                    if (p.protocol.empty() || p.protocol == "Unknown") p.protocol = "GRE";
                    return;
                }
                break;

            // Encrypted tunnels: we can see that they exist and how much they
            // carry, but never what is inside. Say so rather than pretending.
            case 50:
                p.protocol = "ESP";
                p.service = "IPsec (encrypted)";
                p.encryptedTunnel = true;
                return;
            default:
                break;
            }

            if (const char* name = ipProtocolName(l4Proto)) {
                p.protocol = name;
            } else {
                p.protocol = "IP proto " + std::to_string(l4Proto);
            }
        }

        void decodeNetwork(const uint8_t* buffer, size_t end, size_t offset,
                           uint16_t etherType, ParsedPacket& p, int depth) {
            if (depth > kMaxTunnelDepth) return;

            if (etherType == kEthMplsUni || etherType == kEthMplsMul) {
                decodeMpls(buffer, end, offset, p, depth);
                if (p.protocol == "Unknown") p.protocol = "MPLS";
                return;
            }
            if (etherType == kEthPppoeSess) {
                decodePppoe(buffer, end, offset, p, depth);
                if (p.protocol == "Unknown") p.protocol = "PPPoE";
                return;
            }

            if (etherType == kEthIPv4) {
                if (end < offset + sizeof(IPv4Header)) return;
                const uint8_t versionHlen = buffer[offset];
                const size_t ihl = static_cast<size_t>(versionHlen & 0x0F) * 4;
                if ((versionHlen >> 4) != 4 || ihl < sizeof(IPv4Header) || end < offset + ihl) return;

                const uint16_t totalLength = readU16(buffer + offset + 2);
                if (totalLength < ihl) return;
                const size_t packetEnd = std::min(end, offset + static_cast<size_t>(totalLength));

                p.srcIP = ipv4ToString(buffer + offset + 12);
                p.dstIP = ipv4ToString(buffer + offset + 16);

                // Continuation fragments carry no transport header, so there is
                // nothing further to decode. The first fragment (offset 0) falls
                // through and yields ports and any in-line DPI as usual.
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
                // ARP frame: HTYPE(2) PTYPE(2) HLEN(1) PLEN(1) OPER(2)
                //            SHA(HLEN) SPA(PLEN) THA(HLEN) TPA(PLEN)
                if (end < offset + 8) return;
                const uint16_t ptype = readU16(buffer + offset + 2);
                const uint8_t hlen = buffer[offset + 4];
                const uint8_t plen = buffer[offset + 5];
                const uint16_t oper = readU16(buffer + offset + 6);
                const size_t arpBody = offset + 8;
                if (ptype == kEthIPv4 && plen == 4
                    && end >= arpBody + 2 * (static_cast<size_t>(hlen) + plen)) {
                    p.srcIP = ipv4ToString(buffer + arpBody + hlen);
                    p.dstIP = ipv4ToString(buffer + arpBody + 2 * static_cast<size_t>(hlen) + plen);
                }
                p.service = (oper == 1) ? "ARP request" : (oper == 2) ? "ARP reply" : "";
                return;
            }

            if (const char* name = etherTypeName(etherType)) {
                p.protocol = name;
                return;
            }
            p.protocol = "Non-IP";
        }

        // Service labels keyed on the port that looks like the server's. Both
        // directions of a conversation resolve to the same label.
        void classifyTcpPort(uint16_t port, ParsedPacket& p) {
            if (!p.service.empty()) return;
            switch (port) {
                case 21:    p.service = "FTP"; break;
                case 22:    p.service = "SSH"; break;
                case 23:    p.service = "Telnet"; break;
                case 25:    p.service = "SMTP"; break;
                case 53:    p.service = "DNS (TCP)"; break;
                case 80:    p.service = "HTTP"; break;
                case 110:   p.service = "POP3"; break;
                case 143:   p.service = "IMAP"; break;
                case 179:   p.service = "BGP"; break;
                case 389:   p.service = "LDAP"; break;
                case 443:   p.service = "HTTPS"; break;
                case 445:   p.service = "SMB"; break;
                case 465:
                case 587:   p.service = "SMTP+TLS"; break;
                case 514:   p.service = "Syslog"; break;
                case 636:   p.service = "LDAPS"; break;
                case 853:   p.service = "DNS-over-TLS"; break;
                case 993:   p.service = "IMAP+TLS"; break;
                case 995:   p.service = "POP3+TLS"; break;
                case 1433:  p.service = "MSSQL"; break;
                case 1883:  p.service = "MQTT"; break;
                case 3306:  p.service = "MySQL"; break;
                case 3389:  p.service = "RDP"; break;
                case 5060:
                case 5061:  p.service = "SIP"; break;
                case 5222:  p.service = "XMPP"; break;
                case 5432:  p.service = "PostgreSQL"; break;
                case 5900:  p.service = "VNC"; break;
                case 6379:  p.service = "Redis"; break;
                case 6443:  p.service = "Kubernetes API"; break;
                case 6667:  p.service = "IRC"; break;
                case 8000:
                case 8080:
                case 8888:  p.service = "HTTP (alt)"; break;
                case 8443:  p.service = "HTTPS (alt)"; break;
                case 9092:  p.service = "Kafka"; break;
                case 9200:  p.service = "Elasticsearch"; break;
                case 9418:  p.service = "Git"; break;
                case 25565: p.service = "Minecraft"; break;
                case 27017: p.service = "MongoDB"; break;
                default: break;
            }
        }

        void classifyUdpPort(uint16_t port, ParsedPacket& p) {
            if (!p.service.empty()) return;
            switch (port) {
                case 53:    p.service = "DNS"; break;
                case 67:
                case 68:    p.service = "DHCP"; break;
                case 69:    p.service = "TFTP"; break;
                case 123:   p.service = "NTP"; break;
                case 137:
                case 138:
                case 139:   p.service = "NetBIOS"; break;
                case 161:
                case 162:   p.service = "SNMP"; break;
                case 443:   p.service = "QUIC"; break;
                case 500:
                case 4500:  p.service = "IPsec"; break;
                case 514:   p.service = "Syslog"; break;
                case 546:
                case 547:   p.service = "DHCPv6"; break;
                case 784:
                case 8853:  p.service = "DNS-over-QUIC"; break;
                case 853:   p.service = "DNS-over-QUIC"; break;
                case 1194:  p.service = "OpenVPN"; break;
                case 1900:  p.service = "SSDP"; break;
                case 3478:
                case 3479:
                case 5349:  p.service = "STUN/TURN"; break;
                case 4789:  p.service = "VXLAN"; break;
                case 5353:  p.service = "mDNS"; break;
                case 5355:  p.service = "LLMNR"; break;
                case 6081:  p.service = "GENEVE"; break;
                case 51820: p.service = "WireGuard"; break;
                default: break;
            }
        }

        bool isHttpMethod(const uint8_t* p, size_t len, size_t& methodLen) {
            static constexpr std::string_view methods[] = {
                "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS",
                "PATCH", "TRACE", "CONNECT",
            };
            for (std::string_view method : methods) {
                if (len > method.size() + 1
                    && std::memcmp(p, method.data(), method.size()) == 0
                    && p[method.size()] == ' ') {
                    methodLen = method.size();
                    return true;
                }
            }
            return false;
        }

    } // namespace

    bool ProtocolParser::looksLikeTlsHandshake(const uint8_t* payload, size_t length) {
        // Handshake record (0x16), TLS major version 3, minor 0..4.
        return length >= 5 && payload[0] == 0x16 && payload[1] == 0x03 && payload[2] <= 0x04;
    }

    ParsedPacket ProtocolParser::parse(const PacketData& rawData) {
        ParsedPacket parsed;
        parsed.timestamp = rawData.timestamp;
        parsed.length = rawData.length;
        parsed.protocol = "Unknown";

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

        // Application-layer DPI runs once, on the innermost transport payload.
        if (parsed.payloadLength > 0 && parsed.payloadOffset < size) {
            const uint8_t* payload = buffer + parsed.payloadOffset;
            const size_t payloadLen = std::min(parsed.payloadLength, size - parsed.payloadOffset);

            if (parsed.protocol == "TCP") {
                if (looksLikeTlsHandshake(payload, payloadLen)) {
                    parseTLS(payload, payloadLen, parsed);
                } else {
                    parseHTTP(payload, payloadLen, parsed);
                }
                classifyTcpPort(parsed.dstPort, parsed);
                classifyTcpPort(parsed.srcPort, parsed);
            } else if (parsed.protocol == "UDP") {
                // QUIC runs on whatever port the deployment chose; identify it
                // by the long-header + fixed-bit shape and a known version.
                if (QuicParser::looksLikeLongHeader(payload, payloadLen)) {
                    if (auto sni = QuicParser::extractInitialSni(payload, payloadLen)) {
                        parsed.sni = *sni;
                        if (parsed.service.empty()) {
                            parsed.service = identifyService(*sni);
                        }
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

        // Encrypted tunnels that ride on UDP are only recognisable by port.
        if (parsed.service == "WireGuard" || parsed.service == "OpenVPN"
            || parsed.service == "IPsec") {
            parsed.encryptedTunnel = true;
        }

        return parsed;
    }

    bool ProtocolParser::parseTlsClientHello(const uint8_t* payload, size_t len, std::string& outSni) {
        constexpr size_t recordHeaderLength = 5;
        constexpr size_t handshakeHeaderLength = 4;
        constexpr size_t clientHelloFixedLength = 34; // Version + random

        if (!looksLikeTlsHandshake(payload, len)) return false;

        // A truncated record is not a parse failure — the rest of the
        // ClientHello is in the next TCP segment. Report "not yet".
        const size_t recordLength = readU16(payload + 3);
        if (recordHeaderLength + recordLength > len) return false;
        const size_t recordEnd = recordHeaderLength + recordLength;

        size_t pos = recordHeaderLength;
        if (recordEnd < pos + handshakeHeaderLength || payload[pos] != 0x01) return false; // ClientHello

        const size_t handshakeLength = (static_cast<size_t>(payload[pos + 1]) << 16)
            | (static_cast<size_t>(payload[pos + 2]) << 8) | payload[pos + 3];
        pos += handshakeHeaderLength;
        if (pos + handshakeLength > recordEnd) return false;
        const size_t handshakeEnd = pos + handshakeLength;
        if (handshakeEnd < pos + clientHelloFixedLength) return false;
        pos += clientHelloFixedLength;

        if (pos >= handshakeEnd) return false;
        const size_t sessionIdLength = payload[pos++];
        if (sessionIdLength > handshakeEnd - pos) return false;
        pos += sessionIdLength;

        if (handshakeEnd - pos < 2) return false;
        const size_t cipherSuitesLength = readU16(payload + pos);
        pos += 2;
        if (cipherSuitesLength > handshakeEnd - pos) return false;
        pos += cipherSuitesLength;

        if (pos >= handshakeEnd) return false;
        const size_t compressionMethodsLength = payload[pos++];
        if (compressionMethodsLength > handshakeEnd - pos) return false;
        pos += compressionMethodsLength;

        if (handshakeEnd - pos < 2) return false;
        const size_t extensionsLength = readU16(payload + pos);
        pos += 2;
        if (extensionsLength > handshakeEnd - pos) return false;
        const size_t extensionsEnd = pos + extensionsLength;

        while (extensionsEnd - pos >= 4) {
            const uint16_t extensionType = readU16(payload + pos);
            const size_t extensionLength = readU16(payload + pos + 2);
            pos += 4;
            if (extensionLength > extensionsEnd - pos) return false;
            const size_t extensionEnd = pos + extensionLength;

            if (extensionType == 0x0000) { // Server Name Indication
                if (extensionEnd - pos < 2) return false;
                const size_t nameListLength = readU16(payload + pos);
                pos += 2;
                if (nameListLength > extensionEnd - pos) return false;
                const size_t nameListEnd = pos + nameListLength;

                while (nameListEnd - pos >= 3) {
                    const uint8_t nameType = payload[pos++];
                    const size_t nameLength = readU16(payload + pos);
                    pos += 2;
                    if (nameLength > nameListEnd - pos) return false;
                    if (nameType == 0x00) {
                        outSni.assign(reinterpret_cast<const char*>(payload + pos), nameLength);
                        return true;
                    }
                    pos += nameLength;
                }
                return false;
            }

            pos = extensionEnd;
        }
        return false;
    }

    void ProtocolParser::parseTLS(const uint8_t* payload, size_t len, ParsedPacket& outPacket) {
        std::string sni;
        if (parseTlsClientHello(payload, len, sni) && !sni.empty()) {
            outPacket.sni = sni;
            outPacket.service = identifyService(sni);
        }
    }

    void ProtocolParser::parseHTTP(const uint8_t* payload, size_t len, ParsedPacket& outPacket) {
        // Only the head of the message matters, and a header block that has not
        // arrived within 2 KiB is not one we need.
        const size_t scanLen = std::min<size_t>(len, 2048);

        const auto lineEnd = [&](size_t from) {
            for (size_t i = from; i + 1 < scanLen; ++i) {
                if (payload[i] == '\r' && payload[i + 1] == '\n') return i;
            }
            return scanLen;
        };

        if (scanLen >= 12 && std::memcmp(payload, "HTTP/1.", 7) == 0) {
            const size_t end = lineEnd(0);
            outPacket.info.assign(reinterpret_cast<const char*>(payload), end);
            if (outPacket.service.empty()) outPacket.service = "HTTP";
            return;
        }

        size_t methodLen = 0;
        if (!isHttpMethod(payload, scanLen, methodLen)) return;

        // Request line: METHOD SP request-target SP HTTP/1.x
        const size_t requestLineEnd = lineEnd(0);
        outPacket.info.assign(reinterpret_cast<const char*>(payload),
            std::min(requestLineEnd, static_cast<size_t>(120)));
        if (outPacket.service.empty()) outPacket.service = "HTTP";

        // Walk header lines looking for Host.
        size_t pos = requestLineEnd + 2;
        while (pos < scanLen) {
            const size_t end = lineEnd(pos);
            if (end == pos) break; // blank line: end of headers
            if (end == scanLen) break;

            constexpr std::string_view hostPrefix = "host:";
            if (end - pos > hostPrefix.size()) {
                bool isHost = true;
                for (size_t i = 0; i < hostPrefix.size(); ++i) {
                    if (std::tolower(static_cast<unsigned char>(payload[pos + i])) != hostPrefix[i]) {
                        isHost = false;
                        break;
                    }
                }
                if (isHost) {
                    size_t valueStart = pos + hostPrefix.size();
                    while (valueStart < end && payload[valueStart] == ' ') ++valueStart;
                    if (valueStart < end) {
                        outPacket.hostname.assign(
                            reinterpret_cast<const char*>(payload + valueStart), end - valueStart);
                        if (const std::string named = identifyService(outPacket.hostname); !named.empty()) {
                            outPacket.service = named;
                        }
                    }
                    return;
                }
            }
            pos = end + 2;
        }
    }

    std::string ProtocolParser::identifyService(const std::string& hostname) {
        // Substring match against a curated catalog of major services.
        // The map is ordered by specificity — more specific patterns first.
        struct Pattern { std::string_view needle; std::string_view label; };
        static constexpr std::array catalog = std::to_array<Pattern>({
            // Encrypted DNS resolvers. Checked first: these hosts would
            // otherwise match their operator ("Google", "Cloudflare") and hide
            // the fact that name resolution has moved off the wire.
            {"mozilla.cloudflare-dns.com", "DNS-over-HTTPS"},
            {"cloudflare-dns.com",  "DNS-over-HTTPS"},
            {"one.one.one.one",     "DNS-over-HTTPS"},
            {"dns.google",          "DNS-over-HTTPS"},
            {"dns.quad9.net",       "DNS-over-HTTPS"},
            {"doh.opendns.com",     "DNS-over-HTTPS"},
            {"dns.nextdns.io",      "DNS-over-HTTPS"},
            {"doh.cleanbrowsing.org","DNS-over-HTTPS"},
            {"dns.adguard",         "DNS-over-HTTPS"},
            {"doh.dns.sb",          "DNS-over-HTTPS"},

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
            {"anthropic",       "Anthropic"},
            {"openai",          "OpenAI"},

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

        const std::string lower = toLowerCopy(hostname);
        for (const auto& pat : catalog) {
            if (lower.find(pat.needle) != std::string::npos) return std::string(pat.label);
        }
        return {};
    }

} // namespace core
