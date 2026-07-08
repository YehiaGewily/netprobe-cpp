#pragma once

#include "core/PacketData.hpp"
#include "core/ParsedPacket.hpp"
#include "core/ProtocolHeaders.hpp"
#include <cstddef>
#include <string>

namespace core {

    class ProtocolParser {
    public:
        static ParsedPacket parse(const PacketData& rawData);
        static bool looksLikeTlsHandshake(const uint8_t* payload, size_t length);
        static bool parseTlsClientHello(const uint8_t* payload, size_t length, std::string& outSni);
        static std::string identifyService(const std::string& hostname);

    private:
        static void parseTLS(const uint8_t* payload, size_t length, ParsedPacket& outPacket);
        static void parseHTTP(const uint8_t* payload, size_t length, ParsedPacket& outPacket);
    };

} // namespace core
