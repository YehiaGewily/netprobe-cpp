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
        static std::string identifyService(const std::string& hostname);

    private:
        static void parseTLS(const uint8_t* payload, size_t length, ParsedPacket& outPacket);
        static void parseHTTP(const uint8_t* payload, size_t length, ParsedPacket& outPacket);
    };

} // namespace core
