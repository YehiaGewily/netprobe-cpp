#include "core/ProtocolParser.hpp"
#include "core/NetworkPlatform.hpp"
#include <algorithm>
#include <cstring>

namespace core {

    namespace {
        uint16_t readU16(const uint8_t* bytes) {
            return static_cast<uint16_t>(bytes[0]) << 8 | bytes[1];
        }
    }

    ParsedPacket ProtocolParser::parse(const PacketData& rawData) {
        ParsedPacket parsed;
        parsed.timestamp = rawData.timestamp;
        parsed.length = rawData.length;
        parsed.protocol = "Unknown";
        
        const uint8_t* buffer = rawData.payload.data();
        size_t size = rawData.payload.size();
        size_t offset = 0;

        // 1. Ethernet parsing. Read individual bytes rather than dereferencing
        // unaligned headers from an arbitrary capture buffer.
        if (size < sizeof(EthernetHeader)) return parsed;
        offset += sizeof(EthernetHeader);

        uint16_t ethType = readU16(buffer + 12);
        // Support one or more 802.1Q/QinQ VLAN tags before the IP packet.
        while (ethType == 0x8100 || ethType == 0x88A8 || ethType == 0x9100) {
            if (size < offset + 4) return parsed;
            ethType = readU16(buffer + offset + 2);
            offset += 4;
        }

        if (ethType != 0x0800) { // Not IPv4
            parsed.protocol = "Non-IPv4";
            return parsed;
        }

        // 2. IPv4 Parsing
        if (size < offset + sizeof(IPv4Header)) return parsed;
        const uint8_t versionHlen = buffer[offset];
        const uint8_t version = versionHlen >> 4;
        const size_t ihl = (versionHlen & 0x0F) * 4;
        if (version != 4 || ihl < sizeof(IPv4Header) || size < offset + ihl) return parsed;

        const uint16_t totalLength = readU16(buffer + offset + 2);
        if (totalLength < ihl) return parsed;
        const size_t packetEnd = std::min(size, offset + static_cast<size_t>(totalLength));

        uint32_t srcAddr;
        uint32_t dstAddr;
        std::memcpy(&srcAddr, buffer + offset + 12, sizeof(srcAddr));
        std::memcpy(&dstAddr, buffer + offset + 16, sizeof(dstAddr));
        parsed.srcIP = ipToString(srcAddr);
        parsed.dstIP = ipToString(dstAddr);

        const uint16_t flagsAndFragmentOffset = readU16(buffer + offset + 6);
        if ((flagsAndFragmentOffset & 0x1FFF) != 0) {
            parsed.protocol = "IPv4 Fragment";
            return parsed;
        }

        const uint8_t protocol = buffer[offset + 9];
        offset += ihl; // Move past IP header (including options)

        // 3. Layer 4 Parsing
        if (protocol == 6) { // TCP
            parsed.protocol = "TCP";
            if (packetEnd < offset + sizeof(TCPHeader)) return parsed;
            
            parsed.srcPort = readU16(buffer + offset);
            parsed.dstPort = readU16(buffer + offset + 2);
            
            // TCP Header Length (Data Offset) is high 4 bits of dataOffsetReserved, multiplied by 4
            const size_t tcpHeaderLen = (buffer[offset + 12] >> 4) * 4;
            if (tcpHeaderLen < sizeof(TCPHeader) || packetEnd < offset + tcpHeaderLen) return parsed;
            size_t payloadOffset = offset + tcpHeaderLen;
            
            // Check for Payload
            if (payloadOffset < packetEnd) {
                // DPI: Check TLS Client Hello on Port 443
                if (parsed.dstPort == 443 || parsed.srcPort == 443) {
                    parseTLS(buffer + payloadOffset, packetEnd - payloadOffset, parsed);
                }
            }

        } else if (protocol == 17) { // UDP
            parsed.protocol = "UDP";
            if (packetEnd < offset + sizeof(UDPHeader)) return parsed;
            parsed.srcPort = readU16(buffer + offset);
            parsed.dstPort = readU16(buffer + offset + 2);
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
        if (sni.find("discord") != std::string::npos) return "Discord";
        if (sni.find("spotify") != std::string::npos) return "Spotify";
        if (sni.find("youtube") != std::string::npos || sni.find("googlevideo") != std::string::npos) return "YouTube";
        return "";
    }

} // namespace core
