#include "core/ProtocolParser.hpp"
#include <sstream>
#include <iomanip>
#include <vector>
#include <winsock2.h> // For ntohs, ntohl, etc. -> ws2_32 linked in cmake

namespace core {

    ParsedPacket ProtocolParser::parse(const PacketData& rawData) {
        ParsedPacket parsed;
        parsed.timestamp = rawData.timestamp;
        parsed.length = rawData.length;
        parsed.protocol = "Unknown";
        
        const uint8_t* buffer = rawData.payload.data();
        size_t size = rawData.payload.size();
        size_t offset = 0;

        // 1. Ethernet Parsing
        if (size < sizeof(EthernetHeader)) return parsed;
        const EthernetHeader* eth = reinterpret_cast<const EthernetHeader*>(buffer + offset);
        offset += sizeof(EthernetHeader);

        uint16_t ethType = ntohs(eth->type);
        if (ethType != 0x0800) { // Not IPv4
            parsed.protocol = "Non-IPv4";
            return parsed;
        }

        // 2. IPv4 Parsing
        if (size < offset + sizeof(IPv4Header)) return parsed;
        const IPv4Header* ip = reinterpret_cast<const IPv4Header*>(buffer + offset);
        
        // IHL is in the lower 4 bits of the first byte (usually) but actually it's Version(4)+IHL(4) 
        // Logic: Version is high nibble, IHL is low nibble.
        uint8_t ihl = (ip->versionHlen & 0x0F) * 4;
        
        parsed.srcIP = ipToString(ip->srcAddr);
        parsed.dstIP = ipToString(ip->dstAddr);

        offset += ihl; // Move past IP header (options included if any)

        // 3. Layer 4 Parsing
        if (ip->protocol == 6) { // TCP
            parsed.protocol = "TCP";
            if (size < offset + sizeof(TCPHeader)) return parsed;
            const TCPHeader* tcp = reinterpret_cast<const TCPHeader*>(buffer + offset);
            
            parsed.srcPort = ntohs(tcp->srcPort);
            parsed.dstPort = ntohs(tcp->dstPort);
            
            // TCP Header Length (Data Offset) is high 4 bits of dataOffsetReserved, multiplied by 4
            uint8_t tcpHeaderLen = ((tcp->dataOffsetReserved >> 4) & 0x0F) * 4;
            size_t payloadOffset = offset + tcpHeaderLen;
            
            // Check for Payload
            if (payloadOffset < size) {
                // DPI: Check TLS Client Hello on Port 443
                if (parsed.dstPort == 443 || parsed.srcPort == 443) {
                    parseTLS(buffer + payloadOffset, size - payloadOffset, parsed);
                }
            }

        } else if (ip->protocol == 17) { // UDP
            parsed.protocol = "UDP";
            if (size < offset + sizeof(UDPHeader)) return parsed;
            const UDPHeader* udp = reinterpret_cast<const UDPHeader*>(buffer + offset);
            
            parsed.srcPort = ntohs(udp->srcPort);
            parsed.dstPort = ntohs(udp->dstPort);
        }

        return parsed;
    }

    std::string ProtocolParser::ipToString(uint32_t ip) {
        // IP in header is network byte order (Big Endian)
        unsigned char bytes[4];
        bytes[0] = ip & 0xFF;
        bytes[1] = (ip >> 8) & 0xFF;
        bytes[2] = (ip >> 16) & 0xFF;
        bytes[3] = (ip >> 24) & 0xFF;
        
        std::ostringstream oss;
        oss << (int)bytes[0] << "." << (int)bytes[1] << "." << (int)bytes[2] << "." << (int)bytes[3];
        return oss.str();
    }

    void ProtocolParser::parseTLS(const uint8_t* payload, size_t len, ParsedPacket& outPacket) {
        // Minimum length for a Client Hello
        if (len < 43) return;

        // Content Type: 0x16 (Handshake)
        if (payload[0] != 0x16) return;

        // Handshake Version: 0x0301 (TLS 1.0) or 0x0303 (TLS 1.2) - typically 0x0301 in Record Layer
        // Skip Record Layer Header (5 bytes: Type, VerMajor, VerMinor, Length)
        size_t pos = 5;
        if (pos >= len) return;

        // Handshake Type: 0x01 (Client Hello)
        if (payload[pos] != 0x01) return;
        pos++;

        // Skip Length(3), Version(2), Random(32)
        pos += 37; 
        if (pos >= len) return;

        // Session ID Length
        uint8_t sessionIDLen = payload[pos];
        pos += 1 + sessionIDLen;
        if (pos >= len) return;

        // Cipher Suites Length
        if (pos + 2 > len) return;
        uint16_t cipherSuitesLen = ntohs(*reinterpret_cast<const uint16_t*>(payload + pos));
        pos += 2 + cipherSuitesLen;
        if (pos >= len) return;

        // Compression Methods Length
        if (pos + 1 > len) return;
        uint8_t compMethodsLen = payload[pos];
        pos += 1 + compMethodsLen;
        if (pos >= len) return;

        // Extensions Length
        if (pos + 2 > len) return;
        uint16_t extensionsLen = ntohs(*reinterpret_cast<const uint16_t*>(payload + pos));
        pos += 2;
        
        // Loop through extensions
        size_t extensionsEnd = pos + extensionsLen;
        if (extensionsEnd > len) extensionsEnd = len;

        while (pos + 4 <= extensionsEnd) {
            uint16_t extType = ntohs(*reinterpret_cast<const uint16_t*>(payload + pos));
            uint16_t extLen = ntohs(*reinterpret_cast<const uint16_t*>(payload + pos + 2));
            pos += 4;

            if (extType == 0x0000) { // SNI Extension
                // Skip List Length (2)
                if (pos + 2 <= extensionsEnd) {
                    pos += 2;
                    // Skip Name Type (1)
                    if (pos + 1 <= extensionsEnd && payload[pos] == 0x00) { // Host Name
                        pos++;
                        // Name Length (2)
                        if (pos + 2 <= extensionsEnd) {
                            uint16_t nameLen = ntohs(*reinterpret_cast<const uint16_t*>(payload + pos));
                            pos += 2;
                            if (pos + nameLen <= extensionsEnd) {
                                outPacket.sni = std::string(reinterpret_cast<const char*>(payload + pos), nameLen);
                                outPacket.service = identifyService(outPacket.sni);
                            }
                        }
                    }
                }
                return; // Found SNI, done
            }
            pos += extLen;
        }
    }

    std::string ProtocolParser::identifyService(const std::string& sni) {
        if (sni.find("discord") != std::string::npos) return "Discord";
        if (sni.find("spotify") != std::string::npos) return "Spotify";
        if (sni.find("youtube") != std::string::npos || sni.find("googlevideo") != std::string::npos) return "YouTube";
        return "";
    }

} // namespace core
