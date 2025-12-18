#pragma once

#include "core/PacketData.hpp"
#include "core/ParsedPacket.hpp"
#include "core/ProtocolHeaders.hpp"
#include <string>

namespace core {

    class ProtocolParser {
    public:
        // Main parsing function
        static ParsedPacket parse(const PacketData& rawData);

    private:
        // Helper to format IPv4 address
        static std::string ipToString(uint32_t ip);

        // Helper to identify service based on SNI
        static std::string identifyService(const std::string& sni);

        // DPI Logic for TLS
        static void parseTLS(const uint8_t* payload, size_t length, ParsedPacket& outPacket);
    };

} // namespace core
