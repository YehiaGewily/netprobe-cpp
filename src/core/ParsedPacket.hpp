#pragma once

#include <string>
#include <cstdint>

namespace core {

    struct ParsedPacket {
        int64_t timestamp;
        std::string srcIP;
        std::string dstIP;
        uint16_t srcPort = 0;
        uint16_t dstPort = 0;
        std::string protocol; // "TCP", "UDP", "Other"
        uint32_t length;
        
        // DPI Fields
        std::string sni;      // Server Name Indication (if TLS)
        std::string service;  // "Discord", "Spotify", "YouTube", or empty
        
        std::string payloadSummary; // Hex dump or text preview
    };

} // namespace core
